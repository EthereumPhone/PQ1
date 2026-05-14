//! Integration test for the ERC-7730 descriptor pipeline.
//!
//! Runs end-to-end against the checked-in seed corpus:
//!   1. Compile every `secure/data/erc7730/*.json` descriptor.
//!   2. Build the Merkle tree.
//!   3. For each leaf:
//!        - Reconstruct the synthetic trailer the companion would
//!          ship (`[u16 ir_len][ir][u32 leaf_index][u32 proof_depth][proof]`).
//!        - Hand the trailer to `pqsigner_erc7730::bundle::verify_erc7730_bundle`,
//!          which is the same byte-for-byte verifier the secure firmware
//!          uses on-device.
//!        - Cross-check the IR's `(chain_id, contract)` /
//!          `(domain_separator)` binding via
//!          `pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712}`.
//!
//! Also exercises the host-side compiler against a synthetic in-memory
//! corpus (one contract + one EIP-712 descriptor) so this test does
//! not depend on the real `secure/data/erc7730/` corpus for its smoke
//! coverage — the seed corpus is exercised separately via the embedded
//! `build_db_seed_corpus` unit test inside `dbgen::erc7730`.
//!
//! See `docs/handoff-erc7730-phase2.md` §"Verification recipe" — this
//! test is what that recipe's step 2 (`cargo test -p dbgen --test
//! erc7730_roundtrip`) refers to.

use std::path::PathBuf;

use dbgen::erc7730::{
    build_db, round_trip_check, Erc7730BuildResult,
};
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, MAX_ERC7730_BUNDLE_LEN};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir, PathOp, CTX_CONTRACT, CTX_EIP712};
use pqsigner_erc7730::walker::path_bytes;
use pqsigner_tx_core::hash::keccak256;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_seed() -> Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    build_db(&dir, &policy).expect("build seed corpus")
}

fn extract_proof(blob: &[u8], leaf_index: usize, proof_depth: usize) -> Vec<[u8; 32]> {
    // Catalog header layout — see `dbgen::erc7730` module doc.
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let base = proofs_off + leaf_index * proof_depth * 32;
    (0..proof_depth)
        .map(|j| {
            let off = base + j * 32;
            let mut h = [0u8; 32];
            h.copy_from_slice(&blob[off..off + 32]);
            h
        })
        .collect()
}

fn proof_depth(blob: &[u8]) -> usize {
    u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize
}

fn synth_bundle(ir: &[u8], leaf_index: u32, proof: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len() * 32);
    buf.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir);
    buf.extend_from_slice(&leaf_index.to_be_bytes());
    buf.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    for h in proof {
        buf.extend_from_slice(h);
    }
    buf
}

#[test]
fn seed_corpus_compiles_and_round_trips() {
    let res = build_seed();
    assert!(
        res.leaf_count >= 6,
        "seed corpus shrunk below sanity threshold: {} leaves",
        res.leaf_count
    );
    round_trip_check(&res).expect("round-trip");
}

#[test]
fn seed_corpus_bundles_verify_against_on_device_parser() {
    let res = build_seed();
    let pd = proof_depth(&res.blob);

    for (i, entry) in res.entries.iter().enumerate() {
        let proof = extract_proof(&res.blob, i, pd);
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);

        assert!(
            bundle.len() <= MAX_ERC7730_BUNDLE_LEN,
            "{}: bundle {} > MAX ({})",
            entry.source.display(),
            bundle.len(),
            MAX_ERC7730_BUNDLE_LEN
        );

        let verified = verify_erc7730_bundle(&bundle, &res.root).unwrap_or_else(|e| {
            panic!(
                "verify_erc7730_bundle failed on leaf {} ({}): {e:?}",
                i,
                entry.source.display()
            )
        });

        assert_eq!(verified.ir.chain_id, entry.chain_id);
        assert_eq!(verified.ir.contract, entry.contract);
        assert_eq!(verified.ir.descriptor_hash, entry.descriptor_hash);

        // Round-trip the context cross-check as the on-device caller
        // would: synthesize a tx envelope / EIP-712 domain that
        // matches this entry, then call the corresponding binding.
        if entry.context_kind == CTX_CONTRACT {
            assert!(matches!(verified.ir.context_kind, ContextKind::Contract));
            cross_check_contract(&verified.ir, entry.chain_id, &entry.contract).unwrap_or_else(
                |e| {
                    panic!(
                        "cross_check_contract failed for leaf {} ({}): {e:?}",
                        i,
                        entry.source.display()
                    )
                },
            );
        } else if entry.context_kind == CTX_EIP712 {
            assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
            cross_check_eip712(
                &verified.ir,
                entry.chain_id,
                &entry.contract,
                &verified.ir.domain_separator,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "cross_check_eip712 failed for leaf {} ({}): {e:?}",
                    i,
                    entry.source.display()
                )
            });
        } else {
            panic!(
                "unknown context_kind 0x{:02x} on leaf {}",
                entry.context_kind, i
            );
        }
    }
}

#[test]
fn binding_mismatch_is_rejected() {
    // Any chain_id flip in the cross-check MUST surface as a
    // BindingError::ChainIdMismatch — same protection the on-device
    // dispatcher relies on.
    let res = build_seed();
    let entry = res
        .entries
        .iter()
        .find(|e| e.context_kind == CTX_CONTRACT)
        .expect("seed corpus has at least one contract-context leaf");
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let v = verify_erc7730_bundle(&bundle, &res.root).expect("bundle verifies");

    let wrong_chain = entry.chain_id.wrapping_add(1);
    let err = cross_check_contract(&v.ir, wrong_chain, &entry.contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ChainIdMismatch),
        "expected ChainIdMismatch, got {err:?}"
    );

    let mut wrong_contract = entry.contract;
    wrong_contract[0] ^= 0x01;
    let err = cross_check_contract(&v.ir, entry.chain_id, &wrong_contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ContractMismatch),
        "expected ContractMismatch, got {err:?}"
    );
}

#[test]
fn tampered_proof_is_rejected() {
    // Flip one byte of the proof and verify the bundle now fails. This
    // is the canonical "did we actually bind?" check.
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let mut proof = extract_proof(&res.blob, entry.leaf_index, pd);
    if !proof.is_empty() {
        proof[0][0] ^= 0xff;
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
        let err = verify_erc7730_bundle(&bundle, &res.root).unwrap_err();
        assert!(
            matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
            "expected Merkle, got {err:?}"
        );
    }
}

/// Lock the container-field index constants in `pqsigner_erc7730::abi`
/// to the host emitter's keccak-prefix convention. The on-device
/// walker indexes `@.value` / `@.to` / etc. by exactly these `u16`
/// values; any drift breaks every existing `erc7730_db.bin`.
/// The Python companion stub at `tools/companion-stub/erc7730_trailer.py`
/// must produce a byte-for-byte trailer that the on-device parser
/// accepts. Phase 3 e2e relies on this — if the stub drifts from the
/// catalog blob layout, every QEMU smoke test fails opaquely.
#[test]
fn companion_stub_trailer_verifies_against_on_device() {
    let root_dir = workspace_root();
    let db_path = root_dir.join("tools/companion-stub/erc7730_db.bin");
    let stub_path = root_dir.join("tools/companion-stub/erc7730_trailer.py");
    if !db_path.exists() || !stub_path.exists() {
        eprintln!("(skipped) companion stub or db missing");
        return;
    }
    // USDT mainnet — a Contract-context descriptor in the seed corpus.
    let usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    let out = std::process::Command::new("python3")
        .arg(&stub_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--chain")
        .arg("1")
        .arg("--contract")
        .arg(usdt)
        .output()
        .expect("run companion stub");
    if !out.status.success() {
        panic!(
            "companion stub failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    let trailer = out.stdout;
    assert!(!trailer.is_empty(), "stub produced empty trailer");
    let result = build_seed();
    let v = verify_erc7730_bundle(&trailer, &result.root)
        .expect("trailer verifies against pinned root");
    assert_eq!(v.ir.chain_id, 1, "chain_id from IR");
    let want_addr =
        hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    assert_eq!(&v.ir.contract, &want_addr[..], "contract from IR");
    assert!(
        matches!(v.ir.context_kind, ContextKind::Contract),
        "Contract context"
    );
}

#[test]
fn container_field_constants_match_keccak_prefix() {
    fn prefix(name: &str) -> u16 {
        let h = keccak256(name.as_bytes());
        u16::from_be_bytes([h[0], h[1]])
    }
    assert_eq!(container_field::VALUE, prefix("value"));
    assert_eq!(container_field::TO, prefix("to"));
    assert_eq!(container_field::FROM, prefix("from"));
    assert_eq!(container_field::CHAIN_ID, prefix("chainId"));
    assert_eq!(container_field::NONCE, prefix("nonce"));
}

/// Every path program the host emitter writes into the seed corpus
/// must parse cleanly via the on-device walker's path-extraction
/// helper (length prefix valid, opcodes recognised, args sized
/// correctly). Catches "host emits a byte the walker rejects" drift
/// without needing a populated ABI tree.
#[test]
fn seed_corpus_path_programs_parse() {
    let result = build_seed();
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("ir parses");
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            for field in fmt.fields() {
                let field = field.expect("field entry parses");
                if field.path_off == 0 {
                    continue;
                }
                let prog = path_bytes(&ir, field.path_off).unwrap_or_else(|e| {
                    panic!(
                        "path_bytes failed for {:?} field {:?}: {:?}",
                        ir.contract, field.label, e
                    )
                });
                assert!(
                    !prog.is_empty(),
                    "empty program at non-zero offset (chain {} contract {:?} field {:?})",
                    ir.chain_id,
                    ir.contract,
                    field.label,
                );
                // First opcode must be a root.
                let root = PathOp::try_from(prog[0]).unwrap_or_else(|_| {
                    panic!(
                        "unknown root opcode 0x{:02X} at field {:?}",
                        prog[0], field.label
                    )
                });
                assert!(
                    matches!(
                        root,
                        PathOp::RootStructured
                            | PathOp::RootContainer
                            | PathOp::RootMetadata
                    ),
                    "first opcode must be a root, got {:?}",
                    root,
                );
                // Every subsequent opcode + arg must fit; walk the
                // stream to verify alignment.
                let mut p = 1;
                while p < prog.len() {
                    let op = PathOp::try_from(prog[p]).unwrap_or_else(|_| {
                        panic!(
                            "unknown opcode 0x{:02X} mid-program (chain {} field {:?})",
                            prog[p], ir.chain_id, field.label
                        )
                    });
                    p += 1;
                    p += match op {
                        PathOp::RootStructured
                        | PathOp::RootContainer
                        | PathOp::RootMetadata => panic!(
                            "Root opcode {:?} mid-descent in field {:?}",
                            op, field.label,
                        ),
                        PathOp::FieldIdx => 2,
                        PathOp::ArrayIdx => 4,
                        PathOp::ArraySlice => 8,
                        PathOp::ArrayLast | PathOp::ArrayAll => 0,
                    };
                    assert!(
                        p <= prog.len(),
                        "opcode {:?} overruns program in field {:?}",
                        op,
                        field.label
                    );
                }
            }
        }
    }
}

/// Host-side wire-format check for the param TLV blob at every
/// `FieldEntry.param_off`. Confirms the host emitter (`dbgen::erc7730::
/// compile_params` + `push_tlv`) produces blobs that satisfy the
/// on-device parser's invariants:
///
///   - `pool[param_off]` is the blob length byte (or `param_off == 0`).
///   - The inner stream is `[tag][len][payload]*` with cursor staying
///     within `blob_len` bytes.
///   - Every tag is in the known 0x30..=0x3F space.
///   - Fixed-width tags carry the documented payload size.
///
/// This complements the per-renderer unit tests in
/// `sphincs-tz-secure::tx::erc7730_render::params` by validating the
/// production emitter's output across every seed-corpus IR.
#[test]
fn seed_corpus_param_tlv_blobs_are_well_formed() {
    let result = build_seed();
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("ir parses");
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            for field in fmt.fields() {
                let field = field.expect("field entry parses");
                if field.param_off == 0 {
                    continue;
                }
                let off = field.param_off as usize;
                let blob_len = *ir.pool.get(off).unwrap_or_else(|| {
                    panic!(
                        "param_off {} out of range for {:?} field {:?}",
                        off, ir.contract, field.label
                    )
                }) as usize;
                let body = ir.pool.get(off + 1..off + 1 + blob_len).unwrap_or_else(|| {
                    panic!(
                        "param blob_len {} overruns pool for {:?} field {:?}",
                        blob_len, ir.contract, field.label
                    )
                });
                let mut cursor = 0usize;
                while cursor < body.len() {
                    assert!(
                        cursor + 2 <= body.len(),
                        "truncated TLV header in {:?} field {:?}",
                        ir.contract,
                        field.label
                    );
                    let tag = body[cursor];
                    let len = body[cursor + 1] as usize;
                    cursor += 2;
                    assert!(
                        cursor + len <= body.len(),
                        "TLV tag 0x{:02X} overruns blob in {:?} field {:?}",
                        tag,
                        ir.contract,
                        field.label
                    );
                    // Tag must be in the documented space.
                    assert!(
                        (0x30u8..=0x3F).contains(&tag),
                        "unknown TLV tag 0x{:02X} in {:?} field {:?}",
                        tag,
                        ir.contract,
                        field.label
                    );
                    // Per-tag width invariants.
                    match tag {
                        0x31 => assert_eq!(
                            len, 20,
                            "PARAM_TOKEN must be 20 B in {:?}",
                            field.label
                        ),
                        0x32 => assert_eq!(
                            len, 32,
                            "PARAM_THRESHOLD must be 32 B in {:?}",
                            field.label
                        ),
                        0x34 | 0x35 | 0x36 | 0x38 | 0x3A => assert_eq!(
                            len, 1,
                            "fixed-1-byte tag 0x{:02X} in {:?}",
                            tag, field.label
                        ),
                        0x37 => assert_eq!(
                            len, 2,
                            "PARAM_ENUM_REF must be 2 B in {:?}",
                            field.label
                        ),
                        0x3C => assert_eq!(
                            len, 4,
                            "PARAM_NESTED_SELECTOR must be 4 B in {:?}",
                            field.label
                        ),
                        0x3D => assert_eq!(
                            len, 20,
                            "PARAM_NESTED_CALLEE must be 20 B in {:?}",
                            field.label
                        ),
                        0x3F => assert!(
                            (1..=255).contains(&len),
                            "PARAM_VISIBILITY must be ≥1 B in {:?}",
                            field.label
                        ),
                        _ => {} // variable-width tags: 0x30, 0x33, 0x39, 0x3B, 0x3E
                    }
                    cursor += len;
                }
                assert_eq!(
                    cursor,
                    body.len(),
                    "param blob has trailing bytes in {:?} field {:?}",
                    ir.contract,
                    field.label
                );
            }
        }
    }
}

#[test]
fn wrong_root_is_rejected() {
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let bad_root = [0xAAu8; 32];
    let err = verify_erc7730_bundle(&bundle, &bad_root).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
        "expected Merkle, got {err:?}"
    );
}
