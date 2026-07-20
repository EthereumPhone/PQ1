//! Integration test for the ERC-7730 descriptor pipeline.
//!
//! Runs end-to-end against the checked-in seed corpus:
//!   1. Compile the pinned `secure/data/erc7730-registry/{registry,ercs}`
//!      catalogue under `secure/data/erc7730/policy.toml`.
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
//! not depend on the real `secure/data/erc7730-registry/` corpus for its smoke
//! coverage — the seed corpus is exercised separately via the embedded
//! `build_db_seed_corpus` unit test inside `dbgen::erc7730`.
//!
//! See `docs/archive/handoff-erc7730-phase2.md` §"Verification recipe" — this
//! test is what that recipe's step 2 (`cargo test -p dbgen --test
//! erc7730_roundtrip`) refers to.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

use dbgen::erc7730::{
    build_db, build_db_tolerant, build_db_tolerant_with_erc20_capabilities, load_policy,
    round_trip_check, try_compile_one, Erc7730BuildResult,
};
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, MAX_ERC7730_BUNDLE_LEN};
use pqsigner_erc7730::ir::{
    ContextKind, Erc7730Ir, FormatOp, PathOp, Visibility, CTX_CONTRACT, CTX_EIP712,
};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::{
    parse as parse_params, DYNAMIC_KIND_BYTES, WORD_GUARD_EQ, WORD_GUARD_NE,
};
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use sha2::{Digest, Sha256};

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

/// The PROD catalog — the vendored upstream registry, built tolerantly (the
/// corpus switch). This is what `tools/companion-stub/erc7730_db.bin` and the
/// firmware-pinned `ERC7730_DESCRIPTORS_ROOT` are built from, so a companion
/// trailer cut from that blob must verify against THIS root.
fn build_registry() -> Erc7730BuildResult {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build exact production ERC20 capability corpus");
    let (res, _skips) = build_db_tolerant_with_erc20_capabilities(
        &reg.join("registry"),
        &policy,
        Some(&reg),
        &erc20.capabilities,
    )
    .expect("build registry corpus");
    res
}

fn build_e2e() -> Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730-e2e");
    let policy = root.join("secure/data/erc7730/policy.toml");
    build_db(&dir, &policy).expect("build E2E corpus")
}

#[test]
fn registry_allowance_threshold_curations_are_structurally_exact() {
    let root = workspace_root();
    let curated_root = root.join("secure/data/erc7730/curations/files");
    let installed_root = root.join("secure/data/erc7730-registry");
    let curated_paths = [
        "ercs/calldata-erc20-tokens.json",
        "registry/flyingtulip/calldata-PositionsManager.json",
        "registry/tether/calldata-usdt.json",
        "registry/walletconnect/calldata-wct.json",
    ];
    for relative in curated_paths {
        let curated = std::fs::read(curated_root.join(relative))
            .unwrap_or_else(|error| panic!("read curated {relative}: {error}"));
        let installed = std::fs::read(installed_root.join(relative))
            .unwrap_or_else(|error| panic!("read installed {relative}: {error}"));
        assert_eq!(
            installed, curated,
            "installed descriptor diverged from its receipted curation: {relative}"
        );
    }

    // The generic ERC-20 support descriptor is not itself a catalogue leaf,
    // so bind its no-threshold policy directly as well as checking its exact
    // curated/installed byte identity above.
    let generic_erc20: serde_json::Value = serde_json::from_slice(
        &std::fs::read(installed_root.join("ercs/calldata-erc20-tokens.json"))
            .expect("read installed generic ERC-20 descriptor"),
    )
    .expect("parse installed generic ERC-20 descriptor");
    let generic_approve =
        &generic_erc20["display"]["formats"]["approve(address _spender, uint256 _value)"];
    let generic_amount = generic_approve["fields"]
        .as_array()
        .expect("generic ERC-20 approve fields")
        .iter()
        .find(|field| field["path"].as_str() == Some("_value"))
        .expect("generic ERC-20 approve amount field");
    assert!(generic_amount["params"].get("threshold").is_none());
    assert!(generic_amount["params"].get("message").is_none());

    let result = build_registry();
    let approve_selector: [u8; 4] = keccak256(b"approve(address,uint256)")[..4]
        .try_into()
        .expect("approve selector width");

    let wct_contract: [u8; 20] = hex::decode("ef4461891dfb3ac8572ccf7c794664a8dd927945")
        .expect("valid WCT deployment")
        .try_into()
        .expect("WCT address width");
    let expected_wct: BTreeSet<_> = [1u64, 10, 8_453]
        .into_iter()
        .map(|chain_id| (chain_id, wct_contract))
        .collect();
    let wct_entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wct.json")
        })
        .collect();
    assert_eq!(
        wct_entries
            .iter()
            .map(|entry| (entry.chain_id, entry.contract))
            .collect::<BTreeSet<_>>(),
        expected_wct
    );
    for entry in wct_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated WCT IR parses");
        let approve = ir
            .find_format_by_selector(&approve_selector)
            .expect("WCT format table parses")
            .expect("WCT approve remains admitted");
        let fields: Vec<_> = approve
            .fields()
            .map(|field| field.expect("WCT approve field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].label, b"Amount");
        assert_eq!(
            FormatOp::try_from(fields[1].format_op),
            Ok(FormatOp::TokenAmount)
        );
        let amount = parse_params(&ir, fields[1].param_off).expect("WCT amount params parse");
        assert_eq!(amount.threshold.copied(), Some([0xff; 32]));
        assert!(
            amount.message.is_none(),
            "WCT uses the trusted default wording"
        );
    }

    let flying_tulip_entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-PositionsManager.json")
        })
        .collect();
    let expected_flying_tulip: BTreeSet<(u64, [u8; 20])> = [
        (1, "be4050a73a7fb384c65e885a15c33461a4b20055"),
        (146, "be4050a73a7fb384c65e885a15c33461a4b20055"),
        (146, "82ffb119eeed117bae7a2cf38ce52eaba3871821"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        (
            chain_id,
            hex::decode(address)
                .expect("valid Flying Tulip deployment")
                .try_into()
                .expect("Flying Tulip address width"),
        )
    })
    .collect();
    assert_eq!(
        flying_tulip_entries
            .iter()
            .map(|entry| (entry.chain_id, entry.contract))
            .collect::<BTreeSet<_>>(),
        expected_flying_tulip
    );
    for entry in flying_tulip_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Flying Tulip IR parses");
        for (signature, amount_ordinal) in [
            ("borrow(address,uint256)", 0usize),
            ("approveBorrow(address,address,uint256)", 1usize),
        ] {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("Flying Tulip selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Flying Tulip format table parses")
                .unwrap_or_else(|| panic!("Flying Tulip route missing: {signature}"));
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("Flying Tulip field parses"))
                .collect();
            let amount = parse_params(&ir, fields[amount_ordinal].param_off)
                .expect("Flying Tulip amount params parse");
            assert!(amount.threshold.is_none(), "{signature} gained a shorthand");
            assert!(
                amount.message.is_none(),
                "{signature} gained threshold wording"
            );
        }

        let engine_selector: [u8; 4] = keccak256(b"approveEngine(address,address,uint256)")[..4]
            .try_into()
            .expect("approveEngine selector width");
        let engine = ir
            .find_format_by_selector(&engine_selector)
            .expect("Flying Tulip format table parses")
            .expect("approveEngine remains admitted");
        let engine_fields: Vec<_> = engine
            .fields()
            .map(|field| field.expect("approveEngine field parses"))
            .collect();
        assert_eq!(engine_fields.len(), 2);
        let allowance = parse_params(&ir, engine_fields[1].param_off)
            .expect("approveEngine allowance params parse");
        assert_eq!(allowance.threshold.copied(), Some([0xff; 32]));
        assert_eq!(allowance.message, Some(b"Unlimited".as_slice()));
    }

    let usdt_entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-usdt.json")
        })
        .collect();
    let expected_usdt: BTreeSet<(u64, [u8; 20])> = [
        (1, "dac17f958d2ee523a2206206994597c13d831ec7"),
        (137, "c2132d05d31c914a87c6611c10748aeb04b58e8f"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        (
            chain_id,
            hex::decode(address)
                .expect("valid USDT deployment")
                .try_into()
                .expect("USDT address width"),
        )
    })
    .collect();
    assert_eq!(
        usdt_entries
            .iter()
            .map(|entry| (entry.chain_id, entry.contract))
            .collect::<BTreeSet<_>>(),
        expected_usdt
    );
    for entry in usdt_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated USDT IR parses");
        let approve = ir
            .find_format_by_selector(&approve_selector)
            .expect("USDT format table parses")
            .expect("USDT approve remains admitted");
        let fields: Vec<_> = approve
            .fields()
            .map(|field| field.expect("USDT approve field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        let amount = parse_params(&ir, fields[1].param_off).expect("USDT amount params parse");
        assert!(amount.threshold.is_none());
        assert!(amount.message.is_none());
    }
}

#[test]
fn registry_morpho_blue_assets_bind_the_signed_market_token_on_both_chains() {
    let root = workspace_root();
    let relative = "registry/morpho/calldata-MorphoBlue.json";
    let curated = std::fs::read(
        root.join("secure/data/erc7730/curations/files")
            .join(relative),
    )
    .expect("read curated Morpho descriptor");
    let installed = std::fs::read(root.join("secure/data/erc7730-registry").join(relative))
        .expect("read installed Morpho descriptor");
    assert_eq!(
        installed, curated,
        "installed Morpho descriptor diverged from its receipted curation"
    );
    let descriptor: serde_json::Value =
        serde_json::from_slice(&installed).expect("parse curated Morpho descriptor");
    assert!(descriptor["_curation_note"]
        .as_str()
        .expect("Morpho curation note")
        .contains("exact signed market loan/collateral token identity"));

    let result = build_registry();
    let contract: [u8; 20] = hex::decode("bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb")
        .expect("valid Morpho address")
        .try_into()
        .expect("Morpho address width");
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-MorphoBlue.json")
        })
        .collect();
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.chain_id, entry.contract))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(1u64, contract), (8_453u64, contract)])
    );

    let admitted = [
        (
            "borrow((address,address,address,address,uint256),uint256,uint256,address,address)",
            0u16,
            true,
        ),
        (
            "withdraw((address,address,address,address,uint256),uint256,uint256,address,address)",
            0u16,
            true,
        ),
        (
            "withdrawCollateral((address,address,address,address,uint256),uint256,address,address)",
            1u16,
            false,
        ),
    ];
    let refused = [
        "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
    ];

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Morpho IR parses");
        assert_eq!(
            ir.format_iter().count(),
            admitted.len(),
            "only the callback-free Morpho routes may be advertised"
        );
        for (signature, token_member, has_shares) in admitted {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("Morpho selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Morpho format table parses")
                .unwrap_or_else(|| panic!("Morpho route missing: {signature}"));
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("Morpho field parses"))
                .collect();
            assert_eq!(fields[5].label, b"Assets");
            assert_eq!(
                FormatOp::try_from(fields[5].format_op),
                Ok(FormatOp::TokenAmount),
                "{signature} assets regressed to an unscaled raw word"
            );
            assert_eq!(
                ir.path_bytes(fields[5].path_off)
                    .expect("Morpho assets path parses"),
                [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 5],
                "{signature} assets must bind ABI head word 5"
            );
            let params = parse_params(&ir, fields[5].param_off).expect("Morpho asset params parse");
            assert_eq!(
                params.token_path,
                Some(
                    &[
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        0,
                        0,
                        PathOp::FieldIdx as u8,
                        (token_member >> 8) as u8,
                        token_member as u8,
                    ][..]
                ),
                "{signature} assets bound the wrong market token member"
            );
            if has_shares {
                assert_eq!(fields[6].label, b"Shares");
                assert_eq!(
                    FormatOp::try_from(fields[6].format_op),
                    Ok(FormatOp::Raw),
                    "state-dependent Morpho shares must remain exact raw units"
                );
            }
        }

        for signature in refused {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("Morpho selector width");
            assert!(
                ir.find_format_by_selector(&selector)
                    .expect("Morpho format table parses")
                    .is_none(),
                "callback-bearing route became clear-signable: {signature}"
            );
            assert!(
                result
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "refused Morpho route left the exact known-call inventory: {signature}"
            );
        }
    }
}

#[test]
fn registry_aave_v3_lending_refuses_pq_incompatible_permits_on_every_deployment() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-lpv3.json")
        })
        .collect();
    assert_eq!(
        entries.len(),
        15,
        "the duplicate Linea declaration must dedupe to 15 unique Aave V3 Pools"
    );

    let accepted = [
        (
            "borrow(address,uint256,uint256,uint16,address)",
            4usize,
            3usize,
        ),
        ("deposit(address,uint256,address,uint16)", 3, 2),
        ("supply(address,uint256,address,uint16)", 3, 2),
    ];
    let still_refused = [
        "repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)",
        "supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)",
        "multicall(bytes[])",
    ];

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Aave V3 IR parses");
        for (signature, field_count, referral_ordinal) in accepted {
            let hash = keccak256(signature.as_bytes());
            let selector: [u8; 4] = hash[..4].try_into().expect("selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Aave format table parses")
                .unwrap_or_else(|| {
                    panic!(
                        "{signature} missing for chain {} contract 0x{}",
                        entry.chain_id,
                        hex::encode(entry.contract)
                    )
                });
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("generated Aave field parses"))
                .collect();
            assert_eq!(
                fields.len(),
                field_count,
                "unexpected fields for {signature}"
            );
            let referral = &fields[referral_ordinal];
            assert_eq!(referral.label, b"Referral Code");
            assert_eq!(
                FormatOp::try_from(referral.format_op),
                Ok(FormatOp::Raw),
                "referralCode must expose its complete signed ABI word"
            );
            let params = parse_params(&ir, referral.param_off).expect("referral params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
        }

        for signature in still_refused {
            let hash = keccak256(signature.as_bytes());
            let selector: [u8; 4] = hash[..4].try_into().expect("selector width");
            assert!(
                ir.find_format_by_selector(&selector)
                    .expect("Aave format table parses")
                    .is_none(),
                "PQ-incompatible or incomplete Aave format became clear-signable: {signature}"
            );
            assert!(
                result
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "refused Aave route must stay in the exact known-call inventory: {signature}"
            );
            assert!(
                known_call_may_contain(
                    &result.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &selector,
                ),
                "refused Aave route must remain fail-closed in the Bloom: {signature}"
            );
        }
    }

    assert_eq!(
        result.entries.len(),
        437,
        "PQ-incompatible permit removal must preserve the 437-leaf catalogue"
    );
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.known_call_set_hash),
        "593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781",
        "permit refusal must not change the declared known-call tuple set"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&result.known_calls_bloom)),
        "af61b17f4bddd54b0a7b9840b01517cffdd0e80f23f85ba0bb7abc30540bb628",
        "permit refusal must not change the known-call Bloom"
    );
}

#[test]
fn registry_weth9_deposit_and_withdraw_bind_exact_values_and_deployments() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-weth.json")
        })
        .collect();
    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        (11_155_111, "fff9976782d46cc05630d1f6ebab18b2324d6b14"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let contract: [u8; 20] = hex::decode(address)
            .expect("valid WETH9 deployment")
            .try_into()
            .expect("WETH9 address width");
        (chain_id, contract)
    })
    .collect();
    let actual_deployments: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract))
        .collect();
    assert_eq!(actual_deployments, expected_deployments);

    let deposit_selector: [u8; 4] = keccak256(b"deposit()")[..4]
        .try_into()
        .expect("selector width");
    assert_eq!(deposit_selector, [0xd0, 0xe3, 0x0d, 0xb0]);
    let withdraw_selector: [u8; 4] = keccak256(b"withdraw(uint256)")[..4]
        .try_into()
        .expect("selector width");
    assert_eq!(withdraw_selector, [0x2e, 0x1a, 0x7d, 0x4d]);
    let mut value_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
    value_path.extend_from_slice(&container_field::VALUE.to_be_bytes());
    let withdraw_amount_path = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
    let mut token_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
    token_path.extend_from_slice(&container_field::TO.to_be_bytes());

    for entry in entries {
        assert_eq!(entry.ir_bytes.len(), 218, "WETH9 IR size drifted");
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated WETH9 IR parses");
        let formats: Vec<_> = ir
            .format_iter()
            .map(|format| format.expect("WETH9 format parses"))
            .collect();
        assert_eq!(
            formats.len(),
            2,
            "WETH9 admits deposit() and withdraw(uint256)"
        );
        let deposit = ir
            .find_format_by_selector(&deposit_selector)
            .expect("WETH9 format table parses")
            .expect("deposit() remains admitted");
        assert_eq!(deposit.intent, b"Wrap");
        assert_eq!(deposit.static_head_words, 0);
        let fields: Vec<_> = deposit
            .fields()
            .map(|field| field.expect("WETH9 field parses"))
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, b"Amount");
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::Amount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("WETH9 value path parses"),
            value_path,
            "deposit amount must bind the authenticated transaction value"
        );
        let params = parse_params(&ir, fields[0].param_off).expect("WETH9 params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(params.integer_width_bytes, Some(32));
        assert!(result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, deposit_selector)));

        let withdraw = ir
            .find_format_by_selector(&withdraw_selector)
            .expect("WETH9 format table parses")
            .expect("withdraw(uint256) is admitted only on the pinned deployments");
        assert_eq!(withdraw.intent, b"Unwrap");
        assert_eq!(withdraw.static_head_words, 1);
        let fields: Vec<_> = withdraw
            .fields()
            .map(|field| field.expect("WETH9 withdraw field parses"))
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, b"Amount");
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::TokenAmount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("WETH9 withdraw amount path parses"),
            withdraw_amount_path,
            "withdraw amount must bind calldata word zero"
        );
        let params =
            parse_params(&ir, fields[0].param_off).expect("WETH9 withdraw amount params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(params.integer_width_bytes, Some(32));
        assert_eq!(
            params.token_path,
            Some(token_path.as_slice()),
            "withdraw amount must bind token identity to the exact transaction target"
        );
        assert!(result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, withdraw_selector)));
    }

    assert_eq!(result.entries.len(), 437);
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.root),
        "99e4b2556f5a77d6e7d9b8f07b067e9b87a4187b3e472375e602877a2810bcfe"
    );
}

#[test]
fn registry_aave_v2_basic_lending_admits_only_referral_complete_routes() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-lpv2.json")
        })
        .collect();

    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"),
        (137, "8dff5e27ea6b7ac08ebfdf9eb090f32ee9a30fcf"),
        (43_114, "4f01aed16d97e3ab5ab2b501154dc9bb0f1a5a2c"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let decoded = hex::decode(address).expect("valid deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        (chain_id, contract)
    })
    .collect();
    let actual_deployments: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract))
        .collect();
    assert_eq!(actual_deployments, expected_deployments);

    let expected_signatures = [
        "repay(address,uint256,uint256,address)",
        "setUserUseReserveAsCollateral(address,bool)",
        "withdraw(address,uint256,address)",
        "swapBorrowRateMode(address,uint256)",
        "borrow(address,uint256,uint256,uint16,address)",
        "deposit(address,uint256,address,uint16)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = expected_signatures
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let newly_admitted = [
        (
            "borrow(address,uint256,uint256,uint16,address)",
            4usize,
            3usize,
        ),
        ("deposit(address,uint256,address,uint16)", 3, 2),
    ];

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Aave V2 IR parses");
        let actual_selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("Aave V2 format parses").selector)
            .collect();
        assert_eq!(
            actual_selectors, expected_selectors,
            "the curation must change only the two previously refused formats"
        );

        for (signature, field_count, referral_ordinal) in newly_admitted {
            let hash = keccak256(signature.as_bytes());
            let selector: [u8; 4] = hash[..4].try_into().expect("selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Aave V2 format table parses")
                .unwrap_or_else(|| {
                    panic!(
                        "{signature} missing for chain {} contract 0x{}",
                        entry.chain_id,
                        hex::encode(entry.contract)
                    )
                });
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("generated Aave V2 field parses"))
                .collect();
            assert_eq!(fields.len(), field_count);
            let referral = &fields[referral_ordinal];
            assert_eq!(referral.label, b"Referral Code");
            assert_eq!(FormatOp::try_from(referral.format_op), Ok(FormatOp::Raw));
            let params = parse_params(&ir, referral.param_off).expect("referral params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
            assert!(
                result
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "newly clear-signable tuple was not already in the exact known-call inventory"
            );
        }
    }

    assert_eq!(
        result.entries.len(),
        437,
        "Aave V2 already owned three leaves"
    );
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.known_call_set_hash),
        "593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&result.known_calls_bloom)),
        "af61b17f4bddd54b0a7b9840b01517cffdd0e80f23f85ba0bb7abc30540bb628"
    );
}

fn assert_stakewise_claim_format(ir: &Erc7730Ir<'_>, format_name: &str) {
    let selector: [u8; 4] = keccak256(b"claimExitedAssets(uint256,uint256,uint256)")[..4]
        .try_into()
        .expect("selector width");
    let claim = ir
        .find_format_by_selector(&selector)
        .expect("StakeWise claim format table parses")
        .unwrap_or_else(|| panic!("{format_name} claim route is admitted"));
    let fields: Vec<_> = claim
        .fields()
        .map(|field| field.expect("generated StakeWise claim field parses"))
        .collect();
    assert_eq!(fields.len(), 4);

    let expected = [
        (b"Claim receiver".as_slice(), FormatOp::AddressName),
        (b"Position Ticket".as_slice(), FormatOp::Raw),
        (b"Exit initiated at".as_slice(), FormatOp::Date),
        (b"Exit Queue Index".as_slice(), FormatOp::Raw),
    ];
    for (field, (label, op)) in fields.iter().zip(expected) {
        assert_eq!(field.label, label);
        assert_eq!(FormatOp::try_from(field.format_op), Ok(op));
        let params = parse_params(ir, field.param_off).expect("claim field params parse");
        assert_eq!(params.visibility, Visibility::Always);
    }

    let mut sender_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
    sender_path.extend_from_slice(&container_field::FROM.to_be_bytes());
    assert_eq!(
        ir.path_bytes(fields[0].path_off)
            .expect("claim receiver path parses"),
        sender_path,
        "the visible claim receiver must bind the authenticated @.from container field"
    );
    let receiver_params =
        parse_params(ir, fields[0].param_off).expect("claim receiver params parse");
    assert_eq!(receiver_params.addr_types, Some(0x07));
    assert_eq!(receiver_params.terminal_kind, Some(TerminalKind::Address));
    for field in [&fields[1], &fields[2], &fields[3]] {
        let params = parse_params(ir, field.param_off).expect("claim scalar params parse");
        assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
    }
    let timestamp_params =
        parse_params(ir, fields[2].param_off).expect("claim timestamp params parse");
    assert_eq!(timestamp_params.date_encoding, Some(0));
}

fn assert_stakewise_exit_format(ir: &Erc7730Ir<'_>, format_name: &str) -> [u8; 4] {
    let selector: [u8; 4] = keccak256(b"enterExitQueue(uint256,address)")[..4]
        .try_into()
        .expect("selector width");
    let exit = ir
        .find_format_by_selector(&selector)
        .expect("StakeWise exit format table parses")
        .unwrap_or_else(|| panic!("{format_name} exit route is admitted"));
    assert_eq!(
        exit.intent, b"Exit vault",
        "{format_name} exit intent must cover both immediate redemption and queued exit"
    );

    let fields: Vec<_> = exit
        .fields()
        .map(|field| field.expect("generated StakeWise exit field parses"))
        .collect();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].label, b"Shares to exit");
    assert_eq!(FormatOp::try_from(fields[0].format_op), Ok(FormatOp::Raw));
    let shares = parse_params(ir, fields[0].param_off).expect("exit shares params parse");
    assert_eq!(shares.visibility, Visibility::Always);
    assert_eq!(shares.terminal_kind, Some(TerminalKind::Unsigned));
    assert_eq!(shares.integer_width_bytes, Some(32));
    assert_eq!(
        shares.token_path, None,
        "exit shares must not imply live token metadata"
    );
    assert_eq!(
        shares.token, None,
        "exit shares must remain an exact raw word"
    );

    assert_eq!(fields[1].label, b"Exit receiver");
    assert_eq!(
        FormatOp::try_from(fields[1].format_op),
        Ok(FormatOp::AddressName)
    );
    let receiver = parse_params(ir, fields[1].param_off).expect("exit receiver params parse");
    assert_eq!(receiver.visibility, Visibility::Always);
    assert_eq!(receiver.terminal_kind, Some(TerminalKind::Address));

    selector
}

#[test]
fn registry_serenita_admits_operand_complete_deposit_and_claim_routes() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-EthVault.json")
        })
        .collect();
    assert_eq!(entries.len(), 1, "Serenita has one pinned deployment");
    let entry = entries[0];
    assert_eq!(entry.chain_id, 1);
    assert_eq!(
        hex::encode(entry.contract),
        "b36fc5e542cb4fc562a624912f55da2758998113"
    );

    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Serenita IR parses");
    let expected_signatures = [
        "claimExitedAssets(uint256,uint256,uint256)",
        "deposit(address,address)",
        "enterExitQueue(uint256,address)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = expected_signatures
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let actual_selectors: BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("Serenita format parses").selector)
        .collect();
    assert_eq!(
        actual_selectors, expected_selectors,
        "the curation must admit only deposit and preserve enterExitQueue"
    );

    let deposit_selector: [u8; 4] = keccak256(b"deposit(address,address)")[..4]
        .try_into()
        .expect("selector width");
    let deposit = ir
        .find_format_by_selector(&deposit_selector)
        .expect("Serenita format table parses")
        .expect("Serenita deposit is admitted");
    let fields: Vec<_> = deposit
        .fields()
        .map(|field| field.expect("generated Serenita field parses"))
        .collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].label, b"Shares receiver");
    assert_eq!(
        FormatOp::try_from(fields[0].format_op),
        Ok(FormatOp::AddressName)
    );
    assert_eq!(fields[1].label, b"Amount to stake");
    assert_eq!(
        FormatOp::try_from(fields[1].format_op),
        Ok(FormatOp::Amount)
    );
    assert_eq!(fields[2].label, b"Referrer");
    assert_eq!(
        FormatOp::try_from(fields[2].format_op),
        Ok(FormatOp::Raw),
        "the complete signed referrer ABI word must render"
    );
    let referrer_params = parse_params(&ir, fields[2].param_off).expect("referrer params parse");
    assert_eq!(referrer_params.visibility, Visibility::Always);
    assert_eq!(referrer_params.terminal_kind, Some(TerminalKind::Address));
    assert!(
        result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, deposit_selector)),
        "newly clear-signable deposit was already registry-known"
    );

    let exit_selector = assert_stakewise_exit_format(&ir, "Serenita");
    assert!(
        result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, exit_selector)),
        "Serenita exit route must remain registry-known"
    );

    assert_stakewise_claim_format(&ir, "Serenita");
    let claim_selector: [u8; 4] = keccak256(b"claimExitedAssets(uint256,uint256,uint256)")[..4]
        .try_into()
        .expect("selector width");
    assert!(
        result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, claim_selector)),
        "newly clear-signable Serenita claim was already registry-known"
    );

    for refused in [
        "multicall(bytes[])",
        "updateState((bytes32,int160,uint160,bytes32[]))",
        "updateStateAndDeposit(address,address,(bytes32,int160,uint160,bytes32[]))",
    ] {
        let selector: [u8; 4] = keccak256(refused.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert!(
            ir.find_format_by_selector(&selector)
                .expect("Serenita format table parses")
                .is_none(),
            "unsafe Serenita format unexpectedly became clear-signable: {refused}"
        );
    }

    assert_eq!(result.entries.len(), 437);
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.known_call_set_hash),
        "593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&result.known_calls_bloom)),
        "af61b17f4bddd54b0a7b9840b01517cffdd0e80f23f85ba0bb7abc30540bb628"
    );
}

#[test]
fn registry_p2p_native_vault_admits_claim_on_only_the_pinned_deployments() {
    let result = build_registry();
    let source_name = "calldata-NativeTokenVault.json";
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        })
        .collect();
    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "b72668d6ff7a0e318f83097a754c6aed0f8af034"),
        (560_048, "8f73c1ce7fe0e17f45b317b33620924a94256fbb"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let decoded = hex::decode(address).expect("valid P2P deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        (chain_id, contract)
    })
    .collect();
    let actual_deployments: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract))
        .collect();
    assert_eq!(actual_deployments, expected_deployments);

    let expected_signatures = [
        "claimExitedAssets(uint256,uint256,uint256)",
        "deposit(address,address)",
        "enterExitQueue(uint256,address)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = expected_signatures
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let claim_selector: [u8; 4] = keccak256(b"claimExitedAssets(uint256,uint256,uint256)")[..4]
        .try_into()
        .expect("selector width");

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated P2P vault IR parses");
        let actual_selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("P2P vault format parses").selector)
            .collect();
        assert_eq!(
            actual_selectors, expected_selectors,
            "only the formerly refused claim route may join the two existing P2P formats"
        );
        let deposit_selector: [u8; 4] = keccak256(b"deposit(address,address)")[..4]
            .try_into()
            .expect("selector width");
        let deposit = ir
            .find_format_by_selector(&deposit_selector)
            .expect("P2P vault format table parses")
            .expect("P2P deposit remains admitted");
        let deposit_fields: Vec<_> = deposit
            .fields()
            .map(|field| field.expect("generated P2P deposit field parses"))
            .collect();
        assert_eq!(deposit_fields[0].label, b"Shares receiver");
        let exit_selector = assert_stakewise_exit_format(&ir, "P2P");
        assert!(
            result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, exit_selector)),
            "P2P exit route must remain registry-known"
        );
        assert_stakewise_claim_format(&ir, "P2P");
        assert!(
            result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, claim_selector)),
            "newly clear-signable P2P claim was already registry-known"
        );

        let update_selector: [u8; 4] =
            keccak256(b"updateStateAndDeposit(address,address,(bytes32,int160,uint160,bytes32[]))")
                [..4]
                .try_into()
                .expect("selector width");
        assert!(
            ir.find_format_by_selector(&update_selector)
                .expect("P2P vault format table parses")
                .is_none(),
            "P2P dynamic harvest tuple must remain refused"
        );
    }

    assert_eq!(result.entries.len(), 437);
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.known_call_set_hash),
        "593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&result.known_calls_bloom)),
        "af61b17f4bddd54b0a7b9840b01517cffdd0e80f23f85ba0bb7abc30540bb628"
    );
}

#[test]
fn registry_aave_wrapped_gateway_refuses_pq_incompatible_permit_call() {
    let result = build_registry();
    let source_name = "calldata-WrappedTokenGatewayV3.json";
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        })
        .collect();

    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "d01607c3c5ecaba394d8be377a08590149325722"),
        (10, "5f2508cae9923b02316254026cd43d7902866725"),
        (100, "721b9abab6511b46b9ee83a1aba23bdacb004149"),
        (137, "bc302053db3aa514a3c86b9221082f162b91ad63"),
        (146, "061d8e131f26512348ee5fa42e2df1ba9d6505e9"),
        (324, "ae2b00d676130bdf22582781bbba8f4f21e8b0ff"),
        (1868, "6376d4df995f32f308f2d5049a7a320943023232"),
        (8453, "a0d9c1e9e48ca30c8d8c3b5d69ff5dc1f6dffc24"),
        (9745, "54bdcc37c4143f944a3ee51c892a6cbdf305e7a0"),
        (42161, "5283beced7adf6d003225c13896e536f2d4264ff"),
        (43114, "2825ce5921538d17cc15ae00a8b24ff759c6cdae"),
        (59144, "31a239f3e39c5d8ba6b201ba81ed584492ae960f"),
        (534352, "e79ca44408dae5a57ea2a9594532f1e84d2edaa4"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let decoded = hex::decode(address).expect("valid deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        (chain_id, contract)
    })
    .collect();
    let actual_deployments: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract))
        .collect();
    assert_eq!(actual_deployments, expected_deployments);

    let accepted = [
        ([0x47, 0x4c, 0xf5, 0x3d], "depositETH"),
        ([0xe7, 0x4f, 0x7b, 0x85], "borrowETH"),
    ];
    let permit_hash =
        keccak256(b"withdrawETHWithPermit(address,uint256,address,uint256,uint8,bytes32,bytes32)");
    let permit_selector = permit_hash[..4].try_into().expect("selector width");

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Aave gateway IR parses");
        for (selector, call_name) in accepted {
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Aave gateway format table parses")
                .unwrap_or_else(|| {
                    panic!(
                        "{call_name} missing for chain {} contract 0x{}",
                        entry.chain_id,
                        hex::encode(entry.contract)
                    )
                });
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("generated Aave gateway field parses"))
                .collect();
            assert_eq!(fields.len(), 4, "unexpected fields for {call_name}");
            let referral = &fields[2];
            assert_eq!(referral.label, b"Referral Code");
            assert_eq!(
                FormatOp::try_from(referral.format_op),
                Ok(FormatOp::Raw),
                "{call_name} must expose the complete referral word"
            );
            let params = parse_params(&ir, referral.param_off).expect("referral params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
            assert!(
                result
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "newly clear-signable tuple was not already in the exact known-call inventory"
            );
        }

        assert!(
            ir.find_format_by_selector(&permit_selector)
                .expect("Aave gateway format table parses")
                .is_none(),
            "withdrawETHWithPermit cannot transport a PQSmartWallet signature"
        );
        assert!(
            result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, permit_selector)),
            "refused gateway permit must remain exactly known"
        );
        assert!(
            known_call_may_contain(
                &result.known_calls_bloom,
                entry.chain_id,
                &entry.contract,
                &permit_selector,
            ),
            "refused gateway permit must remain fail-closed in the Bloom"
        );
    }
}

#[test]
fn registry_lido_staking_admits_visible_referrals_on_exact_mainnet_contracts() {
    let result = build_registry();
    let expected = [
        (
            "calldata-stETH.json",
            "ae7ab96520de3a18e5e111b5eaab095312d7fe84",
            [0xa1, 0x90, 0x3e, 0xab],
        ),
        (
            "calldata-wstETH-referral-staker.json",
            "a88f0329c2c4ce51ba3fc619bbf44efe7120dd0d",
            [0x94, 0x6f, 0xe3, 0xe8],
        ),
    ];

    for (source_name, address, selector) in expected {
        let entries: Vec<_> = result
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "{source_name} must emit exactly its one pinned mainnet deployment"
        );
        let entry = entries[0];
        let decoded = hex::decode(address).expect("valid Lido deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        assert_eq!((entry.chain_id, entry.contract), (1, contract));

        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Lido IR parses");
        let format = ir
            .find_format_by_selector(&selector)
            .expect("Lido format table parses")
            .expect("newly admitted Lido staking format");
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("generated Lido field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        let referral = &fields[1];
        assert_eq!(referral.label, b"Referral");
        assert_eq!(FormatOp::try_from(referral.format_op), Ok(FormatOp::Raw));
        let params = parse_params(&ir, referral.param_off).expect("referral params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(TerminalKind::Address));
        assert!(
            result.known_calls.contains(&(1, contract, selector)),
            "newly clear-signable Lido tuple was not already known"
        );
    }
}

#[test]
fn registry_lido_withdrawal_queue_pins_seven_honest_routes_and_sender_semantics() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-WithdrawalQueueERC721.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let entry = entries[0];
    assert_eq!(entry.chain_id, 1);
    assert_eq!(
        hex::encode(entry.contract),
        "889edc2edab5f40e902b864ad4d7ade8e412f9b1"
    );
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Lido queue IR parses");

    let admitted = [
        "approve(address,uint256)",
        "claimWithdrawal(uint256)",
        "safeTransferFrom(address,address,uint256)",
        "setApprovalForAll(address,bool)",
        "transferFrom(address,address,uint256)",
        "requestWithdrawals(uint256[],address)",
        "requestWithdrawalsWstETH(uint256[],address)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = admitted
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let actual_selectors: BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("Lido queue format parses").selector)
        .collect();
    assert_eq!(actual_selectors, expected_selectors);

    let assert_format =
        |signature: &str, intent: &[u8], expected_fields: &[(&[u8], FormatOp, TerminalKind)]| {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Lido queue format table parses")
                .unwrap_or_else(|| panic!("admitted Lido route missing: {signature}"));
            assert_eq!(format.intent, intent);
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("Lido queue field parses"))
                .collect();
            assert_eq!(fields.len(), expected_fields.len());
            for (index, (field, (label, op, terminal))) in
                fields.iter().zip(expected_fields).enumerate()
            {
                assert_eq!(field.label, *label, "wrong label for {signature}");
                assert_eq!(FormatOp::try_from(field.format_op), Ok(*op));
                let params = parse_params(&ir, field.param_off).expect("Lido field params parse");
                assert_eq!(params.visibility, Visibility::Always);
                assert_eq!(params.terminal_kind, Some(*terminal));
                assert_eq!(
                    ir.path_bytes(field.path_off)
                        .expect("Lido field path parses"),
                    [
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        0,
                        u8::try_from(index).expect("field ordinal fits u8"),
                    ],
                    "wrong signed operand path for {signature}"
                );
                if *op == FormatOp::Enum {
                    assert!(params.enum_ref.is_some(), "enum route must bind its table");
                }
            }
            assert!(result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, selector)));
        };

    assert_format(
        "approve(address,uint256)",
        b"Set unstETH NFT approval",
        &[
            (
                b"Approval target",
                FormatOp::AddressName,
                TerminalKind::Address,
            ),
            (b"Request ID", FormatOp::Raw, TerminalKind::Unsigned),
        ],
    );
    assert_format(
        "claimWithdrawal(uint256)",
        b"Claim withdrawal",
        &[(b"Request ID", FormatOp::Raw, TerminalKind::Unsigned)],
    );
    for signature in [
        "safeTransferFrom(address,address,uint256)",
        "transferFrom(address,address,uint256)",
    ] {
        assert_format(
            signature,
            b"Transfer unstETH NFT",
            &[
                (b"From", FormatOp::AddressName, TerminalKind::Address),
                (b"To", FormatOp::AddressName, TerminalKind::Address),
                (b"Request ID", FormatOp::Raw, TerminalKind::Unsigned),
            ],
        );
    }
    assert_format(
        "setApprovalForAll(address,bool)",
        b"Set approval for all unstETH NFTs",
        &[
            (b"Operator", FormatOp::AddressName, TerminalKind::Address),
            (b"Access rights", FormatOp::Enum, TerminalKind::Bool),
        ],
    );

    let sender_zero = [0u8; 20];
    for (signature, intent, amount_label, owner_label) in [
        (
            "requestWithdrawals(uint256[],address)",
            &b"Request Withdrawal"[..],
            &b"Amount"[..],
            &b"Initial NFT owner"[..],
        ),
        (
            "requestWithdrawalsWstETH(uint256[],address)",
            &b"Request withdrawal"[..],
            &b"Amount to withdraw"[..],
            &b"Beneficiary"[..],
        ),
    ] {
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        let format = ir
            .find_format_by_selector(&selector)
            .expect("Lido queue format table parses")
            .unwrap_or_else(|| panic!("admitted Lido request missing: {signature}"));
        assert_eq!(format.intent, intent);
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("Lido request field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].label, amount_label);
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::TokenAmount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("amount array path parses"),
            [
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::ArrayAll as u8,
            ]
        );
        let amount_params = parse_params(&ir, fields[0].param_off).expect("amount params parse");
        assert_eq!(amount_params.visibility, Visibility::Always);
        assert_eq!(amount_params.terminal_kind, Some(TerminalKind::Unsigned));
        assert!(amount_params.sender_addresses.is_none());

        assert_eq!(fields[1].label, owner_label);
        assert_eq!(
            FormatOp::try_from(fields[1].format_op),
            Ok(FormatOp::AddressName)
        );
        assert_eq!(
            ir.path_bytes(fields[1].path_off)
                .expect("owner path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 1,]
        );
        let owner_params = parse_params(&ir, fields[1].param_off).expect("owner params parse");
        assert_eq!(owner_params.visibility, Visibility::Always);
        assert_eq!(owner_params.terminal_kind, Some(TerminalKind::Address));
        assert_eq!(
            owner_params.sender_addresses,
            Some(sender_zero.as_slice()),
            "zero owner must be the only authenticated sender sentinel"
        );
        assert!(result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, selector)));
    }

    let refused = [
        "requestWithdrawalsWithPermit(uint256[],address,(uint256,uint256,uint8,bytes32,bytes32))",
        "requestWithdrawalsWstETHWithPermit(uint256[],address,(uint256,uint256,uint8,bytes32,bytes32))",
        "claimWithdrawals(uint256[],uint256[])",
        "claimWithdrawalsTo(uint256[],uint256[],address)",
    ];
    for signature in refused {
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert!(ir
            .find_format_by_selector(&selector)
            .expect("Lido queue format table parses")
            .is_none());
        assert!(
            result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, selector)),
            "refused known route escaped the omission filter: {signature}"
        );
    }
}

#[test]
fn registry_lido_wsteth_admits_operand_complete_permit_on_exact_mainnet_contract() {
    let result = build_registry();
    let entries: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "wstETH must emit exactly its one pinned mainnet deployment"
    );
    let entry = entries[0];
    assert_eq!(entry.chain_id, 1);
    assert_eq!(
        hex::encode(entry.contract),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"
    );

    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated wstETH IR parses");
    let expected_signatures = [
        "approve(address,uint256)",
        "decreaseAllowance(address,uint256)",
        "increaseAllowance(address,uint256)",
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
        "unwrap(uint256)",
        "wrap(uint256)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = expected_signatures
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let actual_selectors: BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("wstETH format parses").selector)
        .collect();
    assert_eq!(
        actual_selectors, expected_selectors,
        "the curation must add permit without changing the other wstETH routes"
    );

    let permit_selector: [u8; 4] =
        keccak256(b"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")[..4]
            .try_into()
            .expect("selector width");
    assert_eq!(permit_selector, [0xd5, 0x05, 0xac, 0xcf]);
    let permit = ir
        .find_format_by_selector(&permit_selector)
        .expect("wstETH format table parses")
        .expect("operand-complete wstETH permit is admitted");
    let fields: Vec<_> = permit
        .fields()
        .map(|field| field.expect("generated wstETH permit field parses"))
        .collect();
    assert_eq!(fields.len(), 7);

    let expected_fields = [
        (
            b"Owner".as_slice(),
            FormatOp::AddressName,
            TerminalKind::Address,
        ),
        (
            b"Spender".as_slice(),
            FormatOp::AddressName,
            TerminalKind::Address,
        ),
        (
            b"Amount".as_slice(),
            FormatOp::TokenAmount,
            TerminalKind::Unsigned,
        ),
        (
            b"Deadline".as_slice(),
            FormatOp::Date,
            TerminalKind::Unsigned,
        ),
        (b"V".as_slice(), FormatOp::Raw, TerminalKind::Unsigned),
        (b"R".as_slice(), FormatOp::Raw, TerminalKind::FixedBytes),
        (b"S".as_slice(), FormatOp::Raw, TerminalKind::FixedBytes),
    ];
    for (field, (label, op, terminal_kind)) in fields.iter().zip(expected_fields) {
        assert_eq!(field.label, label);
        assert_eq!(FormatOp::try_from(field.format_op), Ok(op));
        let params = parse_params(&ir, field.param_off).expect("permit field params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(terminal_kind));
    }
    assert_eq!(
        parse_params(&ir, fields[0].param_off)
            .expect("owner params parse")
            .addr_types,
        Some(0x03),
        "owner must remain restricted to wallet/EOA address rendering"
    );
    assert_eq!(
        parse_params(&ir, fields[1].param_off)
            .expect("spender params parse")
            .addr_types,
        Some(0x04),
        "spender must remain restricted to contract address rendering"
    );
    assert_eq!(
        parse_params(&ir, fields[3].param_off)
            .expect("deadline params parse")
            .date_encoding,
        Some(0),
        "deadline must render as an exact timestamp"
    );
    assert!(
        result
            .known_calls
            .contains(&(entry.chain_id, entry.contract, permit_selector)),
        "newly clear-signable permit was already registry-known"
    );

    assert_eq!(result.entries.len(), 437);
    assert_eq!(result.known_call_count, 4_544);
    assert_eq!(
        hex::encode(result.known_call_set_hash),
        "593a8c77ccb5323cdd2fc2830af32916722dfc3fb570aa33ca94b7fcdf8dd781"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&result.known_calls_bloom)),
        "af61b17f4bddd54b0a7b9840b01517cffdd0e80f23f85ba0bb7abc30540bb628"
    );
}

#[test]
fn registry_lombard_lbtc_admits_operand_complete_permit_on_exact_deployments() {
    let result = build_registry();
    let expected_deployments = [
        (
            "calldata-lbtc-mainnet.json",
            1u64,
            "8236a87084f8b84306f72007f36f2618a5634494",
        ),
        (
            "calldata-lbtc-sepolia.json",
            11_155_111u64,
            "731efa688f3679688cf60a3993b8658138953ed6",
        ),
    ];
    let expected_signatures = [
        "approve(address,uint256)",
        "burn(uint256)",
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "redeem(uint256)",
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
    ];
    let expected_selectors: BTreeSet<[u8; 4]> = expected_signatures
        .iter()
        .map(|signature| {
            keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect();
    let permit_selector: [u8; 4] =
        keccak256(b"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")[..4]
            .try_into()
            .expect("selector width");
    assert_eq!(permit_selector, [0xd5, 0x05, 0xac, 0xcf]);

    for (source_name, chain_id, address) in expected_deployments {
        let entries: Vec<_> = result
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "{source_name} must emit exactly its one pinned deployment"
        );
        let entry = entries[0];
        assert_eq!(entry.chain_id, chain_id);
        assert_eq!(hex::encode(entry.contract), address);

        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated LBTC IR parses");
        let actual_selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("LBTC format parses").selector)
            .collect();
        assert_eq!(
            actual_selectors, expected_selectors,
            "the curation must add permit without admitting mint or redeemForBtc"
        );

        let permit = ir
            .find_format_by_selector(&permit_selector)
            .expect("LBTC format table parses")
            .expect("operand-complete LBTC permit is admitted");
        let fields: Vec<_> = permit
            .fields()
            .map(|field| field.expect("generated LBTC permit field parses"))
            .collect();
        assert_eq!(fields.len(), 7);

        let expected_fields = [
            (
                b"Owner".as_slice(),
                FormatOp::AddressName,
                TerminalKind::Address,
            ),
            (
                b"Spender".as_slice(),
                FormatOp::AddressName,
                TerminalKind::Address,
            ),
            (
                b"Allowance".as_slice(),
                FormatOp::TokenAmount,
                TerminalKind::Unsigned,
            ),
            (
                b"Valid Until".as_slice(),
                FormatOp::Date,
                TerminalKind::Unsigned,
            ),
            (b"V".as_slice(), FormatOp::Raw, TerminalKind::Unsigned),
            (b"R".as_slice(), FormatOp::Raw, TerminalKind::FixedBytes),
            (b"S".as_slice(), FormatOp::Raw, TerminalKind::FixedBytes),
        ];
        for (field, (label, op, terminal_kind)) in fields.iter().zip(expected_fields) {
            assert_eq!(field.label, label);
            assert_eq!(FormatOp::try_from(field.format_op), Ok(op));
            let params = parse_params(&ir, field.param_off).expect("permit field params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(terminal_kind));
        }
        assert_eq!(
            parse_params(&ir, fields[0].param_off)
                .expect("owner params parse")
                .addr_types,
            Some(0x03),
            "owner must remain restricted to wallet/EOA address rendering"
        );
        assert_eq!(
            parse_params(&ir, fields[1].param_off)
                .expect("spender params parse")
                .addr_types,
            Some(0x07),
            "spender must retain EOA/wallet/contract address rendering"
        );
        assert_eq!(
            parse_params(&ir, fields[3].param_off)
                .expect("deadline params parse")
                .date_encoding,
            Some(0),
            "deadline must render as an exact timestamp"
        );
        assert!(
            result
                .known_calls
                .contains(&(entry.chain_id, entry.contract, permit_selector)),
            "newly clear-signable LBTC permit must already be registry-known"
        );
    }
}

#[test]
fn registry_runtime_token_path_keeps_static_intent_without_interpolation() {
    let result = build_registry();
    let entry = result
        .entries
        .iter()
        .find(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-PositionsManager.json")
                && entry.chain_id == 1
        })
        .expect("mainnet Flying Tulip PositionsManager leaf");
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated leaf parses on device");

    let deposit_hash = keccak256(b"deposit(address,uint256)");
    let deposit_selector: [u8; 4] = deposit_hash[..4].try_into().unwrap();
    let deposit = ir
        .find_format_by_selector(&deposit_selector)
        .unwrap()
        .expect("deposit format survives catalogue policy");
    assert_eq!(deposit.intent, b"Deposit collateral");
    let first = deposit.fields().next().unwrap().unwrap();
    let params = parse_params(&ir, first.param_off).unwrap();
    assert!(
        params.interpolated_intent.is_none(),
        "calldata-derived token identity must not authorize a value-bearing banner"
    );

    // Address interpolation is outside v1. It retains the ordinary static
    // intent and emits no token program rather than resolving an address path
    // directly in the banner renderer.
    let approve_hash = keccak256(b"approveBorrow(address,address,uint256)");
    let approve_selector: [u8; 4] = approve_hash[..4].try_into().unwrap();
    let approve = ir
        .find_format_by_selector(&approve_selector)
        .unwrap()
        .expect("approveBorrow format survives with static intent");
    assert_eq!(approve.intent, b"Approve borrowing");
    for field in approve.fields() {
        let field = field.unwrap();
        assert!(parse_params(&ir, field.param_off)
            .unwrap()
            .interpolated_intent
            .is_none());
    }
}

#[test]
fn registry_scalar_interpolation_enrollment_is_explicit_and_bounded() {
    let result = build_registry();
    let reviewed_candidates: BTreeSet<(String, [u8; 4])> = [
        ("calldata-EpochRewardsVault.json", [0x6e, 0x55, 0x3f, 0x65]),
        ("calldata-EpochRewardsVault.json", [0xb4, 0x60, 0xaf, 0x94]),
        (
            "calldata-LayerswapDepository.json",
            [0xf4, 0x37, 0x1f, 0x63],
        ),
        ("calldata-MintAndRedeem.json", [0xa6, 0x47, 0xe8, 0xec]),
        ("calldata-MintAndRedeem.json", [0xea, 0x20, 0x92, 0xf3]),
        ("calldata-PositionsManager.json", [0x22, 0x86, 0x7d, 0x78]),
        ("calldata-PositionsManager.json", [0x47, 0xe7, 0xef, 0x24]),
        ("calldata-PositionsManager.json", [0x4b, 0x8a, 0x35, 0x29]),
        ("calldata-PositionsManager.json", [0xf3, 0xfe, 0xf3, 0xa3]),
        ("calldata-wstETH.json", [0xde, 0x0e, 0x9a, 0x3e]),
        ("calldata-wstETH.json", [0xea, 0x59, 0x8c, 0xb0]),
    ]
    .into_iter()
    .map(|(source, selector)| (source.to_string(), selector))
    .collect();
    let mut enrolled = BTreeSet::new();
    let mut leaf_format_count = 0usize;
    let mut candidate_deployment_count = 0usize;
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated registry leaf parses");
        for format in ir.format_iter() {
            let format = format.expect("validated format");
            let source = entry
                .source
                .file_name()
                .and_then(|name| name.to_str())
                .expect("utf8 registry filename")
                .to_string();
            candidate_deployment_count +=
                usize::from(reviewed_candidates.contains(&(source.clone(), format.selector)));
            let has_program = format.fields().any(|field| {
                let field = field.expect("validated field");
                parse_params(&ir, field.param_off)
                    .expect("validated params")
                    .interpolated_intent
                    .is_some()
            });
            if has_program {
                leaf_format_count += 1;
                enrolled.insert((source, entry.chain_id, format.selector));
            }
        }
    }

    let expected: BTreeSet<(String, u64, [u8; 4])> = [
        (
            "calldata-EpochRewardsVault.json",
            1,
            [0x6e, 0x55, 0x3f, 0x65],
        ),
        (
            "calldata-EpochRewardsVault.json",
            1,
            [0xb4, 0x60, 0xaf, 0x94],
        ),
        ("calldata-MintAndRedeem.json", 1, [0xa6, 0x47, 0xe8, 0xec]),
        ("calldata-MintAndRedeem.json", 1, [0xea, 0x20, 0x92, 0xf3]),
        ("calldata-wstETH.json", 1, [0xde, 0x0e, 0x9a, 0x3e]),
        ("calldata-wstETH.json", 1, [0xea, 0x59, 0x8c, 0xb0]),
    ]
    .into_iter()
    .map(|(source, chain_id, selector)| (source.to_string(), chain_id, selector))
    .collect();
    assert_eq!(
        enrolled, expected,
        "a registry update changed the explicitly reviewed scalar-interpolation set"
    );
    assert_eq!(
        leaf_format_count, 6,
        "only covered deployment-static token identities may retain interpolation"
    );
    assert_eq!(
        candidate_deployment_count, 78,
        "reviewed candidate set drift"
    );
    assert_eq!(
        candidate_deployment_count - leaf_format_count,
        72,
        "deployment-dynamic or metadata-uncovered candidates must omit the tag"
    );
}

#[test]
fn eip712_hash_only_value_sources_are_not_emitted_to_runtime_catalogue() {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let (catalogue, skips) = build_db_tolerant(&reg.join("registry"), &policy, Some(&reg))
        .expect("build registry corpus");

    // Concrete exploit: all three human-meaningful Hyperliquid Withdraw
    // values are dynamic strings. EIP-712 encodeData contains only their
    // keccak words, so no verified bundle for this source may exist.
    for source_name in ["eip712-withdraw.json", "eip712-SpotOrderCancel.json"] {
        assert!(
            !catalogue.entries.iter().any(|entry| {
                entry.source.file_name().and_then(|n| n.to_str()) == Some(source_name)
            }),
            "{source_name} must not reach the runtime catalogue"
        );
        let skip = skips
            .iter()
            .find(|skip| skip.source.file_name().and_then(|n| n.to_str()) == Some(source_name))
            .unwrap_or_else(|| panic!("missing visible skip record for {source_name}"));
        assert!(
            (skip
                .reason
                .contains("visible EIP-712 terminal type `string`")
                && skip.reason.contains("opaque hash word"))
                || (skip.reason.contains("visible:\"never\"")
                    && skip
                        .reason
                        .contains("every signed non-address operand must be shown")),
            "unexpected {source_name} skip reason: {}",
            skip.reason
        );
    }
}

#[test]
fn registry_declared_but_uncompiled_call_is_still_known() {
    let catalogue = build_registry();
    // 1inch AggregationRouterV5's swap is intentionally not emitted by the
    // strict renderer policy, but it is still a vendored registry-declared
    // shape. It must refuse rather than regain a blind-sign path.
    let raw = hex::decode("1111111254eeb25477b68fb85ed929f73a960582").unwrap();
    let mut contract = [0u8; 20];
    contract.copy_from_slice(&raw);
    let selector = [0x12, 0xaa, 0x3c, 0xaf];
    assert!(known_call_may_contain(
        &catalogue.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));

    let emitted = catalogue.entries.iter().any(|entry| {
        entry.chain_id == 1
            && entry.contract == contract
            && Erc7730Ir::parse(&entry.ir_bytes).is_ok_and(|ir| {
                ir.format_iter()
                    .any(|format| format.is_ok_and(|format| format.selector == selector))
            })
    });
    assert!(
        !emitted,
        "control: this exact format should remain uncompiled"
    );
}

#[test]
fn registry_1inch_native_currency_list_is_authenticated_in_order() {
    let catalogue = build_registry();
    let entry = catalogue
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-AggregationRouterV4-eth.json")
        })
        .expect("the static 1inch V4 ETH formats should now compile");
    let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
    let digest = keccak256(b"clipperSwap(address,address,uint256,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    let format = ir
        .format_iter()
        .map(Result::unwrap)
        .find(|format| format.selector == selector)
        .expect("clipperSwap format survives");

    let expected = {
        let mut addresses = [0u8; 40];
        addresses[..20].fill(0xEE);
        addresses
    };
    let token_amounts: Vec<_> = format
        .fields()
        .map(Result::unwrap)
        .filter(|field| FormatOp::try_from(field.format_op) == Ok(FormatOp::TokenAmount))
        .collect();
    assert_eq!(token_amounts.len(), 2);
    for field in token_amounts {
        let params = parse_params(&ir, field.param_off).unwrap();
        assert_eq!(
            params.native_currency_addresses,
            Some(&expected[..]),
            "{} must authenticate [0xEeee…, 0x0] in descriptor order",
            String::from_utf8_lossy(field.label),
        );
    }
}

#[test]
fn registry_flying_tulip_nft_collections_expand_injectively() {
    let catalogue = build_registry();
    let nft_sources = [
        "calldata-PftNft.json",
        "calldata-PftMarketplace.json",
        "calldata-PutManager.json",
    ];
    let entries: Vec<_> = catalogue
        .entries
        .iter()
        .filter(|entry| {
            entry
                .source
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| nft_sources.contains(&name))
        })
        .collect();
    assert_eq!(
        entries.len(),
        7,
        "three real descriptors expand to seven deployments"
    );

    let mut format_count = 0usize;
    let mut nft_field_count = 0usize;
    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
        for format in ir.format_iter().map(Result::unwrap) {
            format_count += 1;
            for field in format.fields().map(Result::unwrap) {
                if FormatOp::try_from(field.format_op) == Ok(FormatOp::NftName) {
                    nft_field_count += 1;
                    let params = parse_params(&ir, field.param_off).unwrap();
                    assert!(
                        params.nft_collection.is_some() ^ params.nft_collection_path.is_some(),
                        "every accepted nftName field has one authenticated collection identity"
                    );
                    if let Some(path) = params.nft_collection_path {
                        assert_eq!(
                            path,
                            pqsigner_erc7730::render::params::NFT_COLLECTION_TO_PATH.as_slice(),
                            "dbgen must emit only the exact device-supported @.to program"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(
        format_count, 15,
        "the twelve NFT formats plus three operator-approval formats expand"
    );
    assert_eq!(nft_field_count, 12);
}

#[test]
fn registry_flying_tulip_pft_nft_admits_only_injective_operator_approval() {
    let catalogue = build_registry();
    let entries: Vec<_> = catalogue
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-PftNft.json")
        })
        .collect();

    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "a4215daaf3745e14e96e169e0e7706c479ce04f2"),
        (146, "a4215daaf3745e14e96e169e0e7706c479ce04f2"),
        (146, "1d8051c90076faa5b683a3551ee4369d00f99d67"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let decoded = hex::decode(address).expect("valid Flying Tulip deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        (chain_id, contract)
    })
    .collect();
    let actual_deployments: BTreeSet<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract))
        .collect();
    assert_eq!(
        actual_deployments, expected_deployments,
        "pFT NFT must emit exactly its three pinned deployments"
    );

    let approve_selector = [0x09, 0x5e, 0xa7, 0xb3];
    let operator_approval_selector = [0xa2, 0x2c, 0xb4, 0x65];
    let expected_selectors: BTreeSet<[u8; 4]> = [approve_selector, operator_approval_selector]
        .into_iter()
        .collect();

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated pFT NFT IR parses");
        let actual_selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("pFT NFT format parses").selector)
            .collect();
        assert_eq!(
            actual_selectors, expected_selectors,
            "enum curation must add only setApprovalForAll beside approve"
        );

        let approval = ir
            .find_format_by_selector(&operator_approval_selector)
            .expect("pFT NFT format table parses")
            .expect("setApprovalForAll is clear-signable");
        let fields: Vec<_> = approval
            .fields()
            .map(|field| field.expect("generated pFT NFT field parses"))
            .collect();
        assert_eq!(
            fields.len(),
            2,
            "operator approval must expose both operands"
        );

        let operator = &fields[0];
        assert_eq!(operator.label, b"Operator");
        assert_eq!(
            FormatOp::try_from(operator.format_op),
            Ok(FormatOp::AddressName)
        );
        let operator_params = parse_params(&ir, operator.param_off).expect("operator params parse");
        assert_eq!(operator_params.visibility, Visibility::Always);
        assert_eq!(operator_params.terminal_kind, Some(TerminalKind::Address));
        assert_eq!(
            operator_params.addr_types,
            Some(0x04),
            "operator rendering must remain contract-restricted"
        );

        let rights = &fields[1];
        assert_eq!(rights.label, b"Access rights");
        assert_eq!(FormatOp::try_from(rights.format_op), Ok(FormatOp::Enum));
        let rights_params = parse_params(&ir, rights.param_off).expect("rights params parse");
        assert_eq!(rights_params.visibility, Visibility::Always);
        assert_eq!(rights_params.terminal_kind, Some(TerminalKind::Bool));
        let enum_off = rights_params.enum_ref.expect("rights enum reference");
        let deny_word = [0u8; 32];
        let mut grant_word = [0u8; 32];
        grant_word[31] = 1;
        let deny =
            pqsigner_erc7730::render::enums::lookup_enum_label(ir.pool, enum_off, &deny_word)
                .expect("rights enum table is valid")
                .expect("false enum value is enrolled");
        let grant =
            pqsigner_erc7730::render::enums::lookup_enum_label(ir.pool, enum_off, &grant_word)
                .expect("rights enum table is valid")
                .expect("true enum value is enrolled");
        assert_eq!(deny, b"Deny all");
        assert_eq!(grant, b"Grant all");
        assert_ne!(deny, grant, "device-visible enum labels must be injective");

        for selector in expected_selectors.iter().copied() {
            assert!(
                catalogue
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "clear-signable pFT NFT tuple must already be registry-known"
            );
        }
    }
}

#[test]
fn registry_flying_tulip_session_manager_admits_only_injective_static_authority_routes() {
    let catalogue = build_registry();
    let entries: Vec<_> = catalogue
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-SessionManager.json")
        })
        .collect();

    let expected_deployments: BTreeSet<(u64, [u8; 20])> = [
        (1, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
        (1, "f9f3ddf2e96cabef94e2634c326dc6dde99360f8"),
        (56, "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42"),
        (146, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
        (146, "109ae72778a0260571b9767477204f1ce41fbdff"),
        (146, "52ef449d44cc4205fa44bf644dee15611fc30734"),
        (43_114, "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54"),
    ]
    .into_iter()
    .map(|(chain_id, address)| {
        let decoded = hex::decode(address).expect("valid SessionManager deployment address");
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&decoded);
        (chain_id, contract)
    })
    .collect();
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.chain_id, entry.contract))
            .collect::<BTreeSet<_>>(),
        expected_deployments,
        "SessionManager must emit exactly its seven pinned deployments"
    );

    const ADMITTED: [(&str, [u8; 4]); 5] = [
        ("acceptOwnership()", [0x79, 0xba, 0x50, 0x97]),
        ("renounceOwnership()", [0x71, 0x50, 0x18, 0xa6]),
        ("revokeSession(bytes32)", [0xa7, 0xfe, 0xd3, 0x85]),
        ("setAllowedTarget(address,bool)", [0xca, 0x1d, 0xd2, 0x2e]),
        ("transferOwnership(address)", [0xf2, 0xfd, 0xe3, 0x8b]),
    ];
    const REFUSED: [(&str, [u8; 4]); 6] = [
        (
            "createSession(address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32)",
            [0xc1, 0x45, 0x59, 0xe5],
        ),
        (
            "createSessionBySig(address,address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32,bytes)",
            [0x74, 0xd3, 0x6b, 0x01],
        ),
        (
            "invalidateNonceBySig(bytes32,uint256,uint256,address,bytes)",
            [0x90, 0x70, 0x68, 0x97],
        ),
        (
            "revokeSessionBySig(bytes32,uint256,bytes)",
            [0x1f, 0xc1, 0xdb, 0x86],
        ),
        (
            "setAllowedTargets(address[],bool)",
            [0x01, 0xe2, 0xae, 0x55],
        ),
        (
            "validateAndConsume(address,uint256,(bytes32,bytes32,uint256,uint256,address,uint256),bytes,address)",
            [0xce, 0x5c, 0xb6, 0xc0],
        ),
    ];
    for (signature, expected) in ADMITTED.into_iter().chain(REFUSED) {
        assert_eq!(
            &keccak256(signature.as_bytes())[..4],
            expected,
            "pinned selector drift for {signature}"
        );
    }
    let expected_selectors: BTreeSet<_> = ADMITTED.iter().map(|(_, selector)| *selector).collect();

    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated SessionManager IR parses");
        let actual_selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("SessionManager format parses").selector)
            .collect();
        assert_eq!(
            actual_selectors, expected_selectors,
            "only five injective, all-static SessionManager authority routes may be advertised"
        );

        let revoke = ir
            .find_format_by_selector(&[0xa7, 0xfe, 0xd3, 0x85])
            .expect("SessionManager format table parses")
            .expect("revokeSession is clear-signable");
        assert_eq!(revoke.intent, b"Revoke session");
        assert_eq!(revoke.static_head_words, 1);
        let revoke_fields: Vec<_> = revoke
            .fields()
            .map(|field| field.expect("revokeSession field parses"))
            .collect();
        assert_eq!(revoke_fields.len(), 1);
        assert_eq!(revoke_fields[0].label, b"Session ID");
        assert_eq!(
            FormatOp::try_from(revoke_fields[0].format_op),
            Ok(FormatOp::Raw)
        );
        assert_eq!(
            ir.path_bytes(revoke_fields[0].path_off)
                .expect("session ID path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0]
        );
        let revoke_params =
            parse_params(&ir, revoke_fields[0].param_off).expect("session ID params parse");
        assert_eq!(revoke_params.visibility, Visibility::Always);
        assert_eq!(revoke_params.terminal_kind, Some(TerminalKind::FixedBytes));

        let target_access = ir
            .find_format_by_selector(&[0xca, 0x1d, 0xd2, 0x2e])
            .expect("SessionManager format table parses")
            .expect("setAllowedTarget is clear-signable");
        assert_eq!(target_access.intent, b"Update allowed target");
        assert_eq!(target_access.static_head_words, 2);
        let target_fields: Vec<_> = target_access
            .fields()
            .map(|field| field.expect("setAllowedTarget field parses"))
            .collect();
        assert_eq!(target_fields.len(), 2);
        assert_eq!(target_fields[0].label, b"Target");
        assert_eq!(
            FormatOp::try_from(target_fields[0].format_op),
            Ok(FormatOp::AddressName)
        );
        assert_eq!(
            ir.path_bytes(target_fields[0].path_off)
                .expect("target path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0]
        );
        let target_params =
            parse_params(&ir, target_fields[0].param_off).expect("target params parse");
        assert_eq!(target_params.visibility, Visibility::Always);
        assert_eq!(target_params.terminal_kind, Some(TerminalKind::Address));

        assert_eq!(target_fields[1].label, b"Access");
        assert_eq!(
            FormatOp::try_from(target_fields[1].format_op),
            Ok(FormatOp::Enum)
        );
        assert_eq!(
            ir.path_bytes(target_fields[1].path_off)
                .expect("access path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 1]
        );
        let access_params =
            parse_params(&ir, target_fields[1].param_off).expect("access params parse");
        assert_eq!(access_params.visibility, Visibility::Always);
        assert_eq!(access_params.terminal_kind, Some(TerminalKind::Bool));
        let enum_off = access_params.enum_ref.expect("access enum reference");
        let disallow =
            pqsigner_erc7730::render::enums::lookup_enum_label(ir.pool, enum_off, &[0u8; 32])
                .expect("access enum table is valid")
                .expect("false access value is enrolled");
        let mut allow_word = [0u8; 32];
        allow_word[31] = 1;
        let allow =
            pqsigner_erc7730::render::enums::lookup_enum_label(ir.pool, enum_off, &allow_word)
                .expect("access enum table is valid")
                .expect("true access value is enrolled");
        assert_eq!(disallow, b"Disallow");
        assert_eq!(allow, b"Allow");
        assert_ne!(disallow, allow, "access labels must remain injective");

        let transfer = ir
            .find_format_by_selector(&[0xf2, 0xfd, 0xe3, 0x8b])
            .expect("SessionManager format table parses")
            .expect("transferOwnership is clear-signable");
        assert_eq!(transfer.intent, b"Update pending owner");
        assert_eq!(transfer.static_head_words, 1);
        let transfer_fields: Vec<_> = transfer
            .fields()
            .map(|field| field.expect("transferOwnership field parses"))
            .collect();
        assert_eq!(transfer_fields.len(), 1);
        assert_eq!(transfer_fields[0].label, b"Pending owner");
        assert_eq!(
            FormatOp::try_from(transfer_fields[0].format_op),
            Ok(FormatOp::AddressName)
        );
        assert_eq!(
            ir.path_bytes(transfer_fields[0].path_off)
                .expect("pending owner path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0]
        );
        let owner_params =
            parse_params(&ir, transfer_fields[0].param_off).expect("pending owner params parse");
        assert_eq!(owner_params.visibility, Visibility::Always);
        assert_eq!(owner_params.terminal_kind, Some(TerminalKind::Address));

        for (_, selector) in ADMITTED {
            assert!(
                catalogue
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "admitted SessionManager selector must remain exactly registry-known"
            );
        }
        for (signature, selector) in REFUSED {
            assert!(
                ir.find_format_by_selector(&selector)
                    .expect("SessionManager format table parses")
                    .is_none(),
                "unsafe SessionManager route became clear-signable: {signature}"
            );
            assert!(
                catalogue
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "refused SessionManager route left the exact known-call inventory: {signature}"
            );
            assert!(
                known_call_may_contain(
                    &catalogue.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &selector,
                ),
                "refused SessionManager route left the fail-closed Bloom: {signature}"
            );
        }
    }
}

#[test]
fn registry_endpoint_only_route_is_omitted_but_stays_known() {
    let catalogue = build_registry();
    let raw = hex::decode("a5e0829caced8ffdd4de3c43696c57f7d7a678ff").unwrap();
    let mut contract = [0u8; 20];
    contract.copy_from_slice(&raw);
    let digest = keccak256(b"swapExactTokensForTokens(uint256,uint256,address[],address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];

    assert!(known_call_may_contain(
        &catalogue.known_calls_bloom,
        137,
        &contract,
        &selector,
    ));
    assert!(!catalogue.entries.iter().any(|entry| {
        entry.chain_id == 137
            && entry.contract == contract
            && Erc7730Ir::parse(&entry.ir_bytes).is_ok_and(|ir| {
                ir.format_iter()
                    .any(|format| format.is_ok_and(|format| format.selector == selector))
            })
    }));
}

#[test]
fn registry_dropped_tuple_array_call_is_still_known() {
    let catalogue = build_registry();
    let raw = hex::decode("2cc8475177918e8c4d840150b68815a4b6f0f5f3").unwrap();
    let mut contract = [0u8; 20];
    contract.copy_from_slice(&raw);
    let digest = keccak256(b"batchExecute((address,uint256,bytes)[])");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert_eq!(selector, [0x1a, 0x83, 0x3e, 0xe3]);
    assert!(known_call_may_contain(
        &catalogue.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
    assert!(!catalogue.entries.iter().any(|entry| {
        entry.chain_id == 1
            && entry.contract == contract
            && Erc7730Ir::parse(&entry.ir_bytes).is_ok_and(|ir| {
                ir.format_iter()
                    .any(|format| format.is_ok_and(|format| format.selector == selector))
            })
    }));
}

#[test]
fn registry_runtime_dead_opaque_bytes_are_omitted_but_stay_known() {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let (catalogue, skips) = build_db_tolerant(&reg.join("registry"), &policy, Some(&reg)).unwrap();

    for entry in &catalogue.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
        for format in ir.format_iter() {
            for field in format.unwrap().fields() {
                let field = field.unwrap();
                let params = parse_params(&ir, field.param_off).unwrap();
                assert_ne!(
                    params.dynamic_kind,
                    Some(DYNAMIC_KIND_BYTES),
                    "{} emitted an always-rejected opaque-bytes field",
                    entry.source.display(),
                );
            }
        }
    }

    let tbtc_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str()) == Some("calldata-TBTC.json")
        })
        .expect("TBTC opaque-bytes format has an audit-visible skip");
    assert!(tbtc_skip.reason.contains("opaque dynamic `bytes`"));

    let raw = hex::decode("18084fba666a33d37592fa2633fd49a74dd93a88").unwrap();
    let mut contract = [0u8; 20];
    contract.copy_from_slice(&raw);
    let digest = keccak256(b"approveAndCall(address,uint256,bytes)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(known_call_may_contain(
        &catalogue.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

/// ANTI-RECURRENCE GUARD. The vendored upstream registry
/// (`secure/data/erc7730-registry/`) is the SOURCE OF TRUTH and the pinned
/// prod corpus. A hand-authored render-test fixture in `secure/data/erc7730/`
/// must NOT duplicate a registry descriptor by `(chainId, contract)` — that is
/// exactly the redundancy the corpus switch removed (we had hand-authored
/// Aave/Lido/Tether/WETH that the registry already shipped). Render tests must
/// either exercise the REAL registry descriptor (via `build_registry()`), or
/// use a SYNTHETIC, non-registry address. Fails loudly if anyone reintroduces a
/// protocol fixture the registry already covers.
#[test]
fn fixtures_do_not_duplicate_the_registry() {
    use std::collections::BTreeSet;
    let fixtures = build_seed();
    let registry = build_registry();
    let reg: BTreeSet<(u64, [u8; 20])> = registry
        .entries
        .iter()
        .map(|e| (e.chain_id, e.contract))
        .collect();
    let mut dups: Vec<String> = fixtures
        .entries
        .iter()
        .filter(|e| reg.contains(&(e.chain_id, e.contract)))
        .map(|e| {
            format!(
                "  {} — chain {} contract 0x{}",
                e.source.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                e.chain_id,
                hex::encode(e.contract),
            )
        })
        .collect();
    dups.sort();
    dups.dedup();
    assert!(
        dups.is_empty(),
        "hand-authored render fixture(s) in secure/data/erc7730/ duplicate the authoritative \
         vendored registry by (chainId, contract):\n{}\n\
         The registry (secure/data/erc7730-registry/) is the source of truth + the pinned prod \
         corpus. Repoint the render test at the REAL registry descriptor (`build_registry()`), or \
         use a SYNTHETIC non-registry address. Never hand-author a descriptor for a protocol the \
         registry already covers.",
        dups.join("\n"),
    );
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
    // The hand-authored `secure/data/erc7730/` is now a synthetic-only
    // render-test corpus (1 leaf), so the Merkle round-trip runs against the
    // PROD corpus — the vendored registry — which is what `db_roots.rs` pins
    // and where the ≥6-leaf sanity floor still means something.
    let res = build_registry();
    assert!(
        res.leaf_count >= 6,
        "registry corpus shrunk below sanity threshold: {} leaves",
        res.leaf_count
    );
    round_trip_check(&res).expect("round-trip");
}

/// Walk every accepted production leaf through the same zero-copy IR, path,
/// and TLV parsers used by secure-world rendering. This is structural
/// assurance only; it does not claim deployed-contract semantics or ERC-8176
/// provenance.
#[test]
fn registry_all_display_material_is_runtime_parseable() {
    let result = build_registry();
    assert_eq!(result.leaf_count, result.entries.len());

    let mut formats_seen = 0usize;
    let mut fields_seen = 0usize;
    let mut contract_leaves = 0usize;
    let mut eip712_leaves = 0usize;

    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes)
            .unwrap_or_else(|e| panic!("{}: production IR rejects: {e:?}", entry.source.display()));
        match ir.context_kind {
            ContextKind::Contract => {
                contract_leaves += 1;
                assert_eq!(entry.primary_type_hash, [0u8; 32]);
            }
            ContextKind::Eip712 => {
                eip712_leaves += 1;
                let first = ir
                    .format_iter()
                    .next()
                    .expect("accepted EIP-712 leaf has a format")
                    .unwrap();
                assert_eq!(
                    entry.primary_type_hash,
                    first.type_hash,
                    "{}: index must bind the first surviving emitted format",
                    entry.source.display(),
                );
            }
        }

        for format in ir.format_iter() {
            let format = format.unwrap();
            formats_seen += 1;
            assert!(!format.intent.is_empty());
            match ir.context_kind {
                ContextKind::Contract => {
                    assert_eq!(format.type_hash, [0u8; 32]);
                    assert_eq!(format.nested_descent_count, 0);
                }
                ContextKind::Eip712 => {
                    assert_ne!(format.type_hash, [0u8; 32]);
                    assert_eq!(format.selector, format.type_hash[..4]);
                }
            }

            let mut format_fields = 0usize;
            for field in format.fields() {
                let field = field.unwrap();
                format_fields += 1;
                fields_seen += 1;
                assert!(!field.label.is_empty());
                FormatOp::try_from(field.format_op).unwrap();
                let params = parse_params(&ir, field.param_off).unwrap();
                if field.path_off == 0 {
                    match (params.const_value, params.nested_struct) {
                        (Some(_), None) => {
                            assert_eq!(params.terminal_kind, Some(TerminalKind::ConstantText));
                        }
                        (None, Some(nested)) => {
                            assert!(!nested.is_empty());
                            assert_eq!(params.terminal_kind, Some(TerminalKind::NestedStruct));
                        }
                        _ => panic!(
                            "{}: path-less field must be exactly one of a constant annotation or nested-struct anchor",
                            entry.source.display()
                        ),
                    }
                } else {
                    assert!(!ir.path_bytes(field.path_off).unwrap().is_empty());
                }
            }
            assert_eq!(format_fields, format.field_count as usize);
        }
    }

    assert_eq!(contract_leaves + eip712_leaves, result.leaf_count);
    assert!(contract_leaves > 0 && eip712_leaves > 0);
    assert!(formats_seen >= result.leaf_count);
    assert!(fields_seen > formats_seen);
}

#[test]
fn e2e_catalogue_contains_a_real_bound_eip712_leaf() {
    let result = build_e2e();
    let entry = result
        .entries
        .iter()
        .find(|entry| entry.context_kind == CTX_EIP712)
        .expect("E2E catalogue must keep a non-vacuous typed-data leaf");
    assert_ne!(entry.primary_type_hash, [0u8; 32]);

    let proof = extract_proof(&result.blob, entry.leaf_index, proof_depth(&result.blob));
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let verified = verify_erc7730_bundle(&bundle, &result.root)
        .expect("E2E typed-data proof must verify against the E2E root");
    assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
    assert_ne!(verified.ir.domain_separator, [0u8; 32]);
    cross_check_eip712(&verified.ir, entry.chain_id, &verified.ir.domain_separator)
        .expect("generated domain/deployment binding must round-trip");
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
            cross_check_eip712(&verified.ir, entry.chain_id, &verified.ir.domain_separator)
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
        matches!(
            err,
            pqsigner_erc7730::binding::BindingError::ChainIdMismatch
        ),
        "expected ChainIdMismatch, got {err:?}"
    );

    let mut wrong_contract = entry.contract;
    wrong_contract[0] ^= 0x01;
    let err = cross_check_contract(&v.ir, entry.chain_id, &wrong_contract).unwrap_err();
    assert!(
        matches!(
            err,
            pqsigner_erc7730::binding::BindingError::ContractMismatch
        ),
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

fn run_companion_stub(
    stub: &Path,
    db: &Path,
    chain_id: u64,
    contract: &str,
    context: Option<&str>,
    domain_separator: Option<&str>,
    primary_type_hash: Option<&str>,
) -> Output {
    let mut command = std::process::Command::new("python3");
    command
        .arg("-B")
        .arg(stub)
        .arg("--db")
        .arg(db)
        .arg("--chain")
        .arg(chain_id.to_string())
        .arg("--contract")
        .arg(contract);
    if let Some(context) = context {
        command.arg("--context").arg(context);
    }
    if let Some(domain_separator) = domain_separator {
        command.arg("--domain-separator").arg(domain_separator);
    }
    if let Some(primary_type_hash) = primary_type_hash {
        command.arg("--primary-type-hash").arg(primary_type_hash);
    }
    command.output().expect("run companion stub")
}

fn successful_stub_output(output: Output) -> Vec<u8> {
    if !output.status.success() {
        panic!(
            "companion stub failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    assert!(!output.stdout.is_empty(), "stub produced empty trailer");
    output.stdout
}

/// The Python companion stub at `tools/companion-stub/erc7730_trailer.py`
/// must produce byte-for-byte bundles that the on-device parser accepts. The
/// current LBTC deployments each carry BOTH a Contract leaf and an EIP-712
/// `NetworkFeeAuthorization` leaf, so a first `(chain, contract)` match is
/// provably wrong. Exact context + full authenticated-IR type-hash lookup must
/// select the typed leaf, while the no-flag default remains Contract-only.
#[test]
fn companion_stub_context_and_full_type_hash_lookup_verify_on_device() {
    let root_dir = workspace_root();
    let db_path = root_dir.join("tools/companion-stub/erc7730_db.bin");
    let stub_path = root_dir.join("tools/companion-stub/erc7730_trailer.py");
    assert!(db_path.is_file(), "tracked companion catalogue is missing");
    assert!(
        stub_path.is_file(),
        "tracked companion reference is missing"
    );
    let result = build_registry();
    let type_hash_hex = "40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725";
    let type_hash: [u8; 32] = hex::decode(type_hash_hex).unwrap().try_into().unwrap();
    let deployments = [
        (1u64, "8236a87084f8b84306f72007f36f2618a5634494"),
        (11_155_111u64, "731efa688f3679688cf60a3993b8658138953ed6"),
    ];

    for (chain_id, address_hex) in deployments {
        let address_vec = hex::decode(address_hex).unwrap();
        let address: [u8; 20] = address_vec.try_into().unwrap();
        let group: Vec<_> = result
            .entries
            .iter()
            .filter(|entry| entry.chain_id == chain_id && entry.contract == address)
            .collect();
        assert_eq!(
            group.len(),
            2,
            "LBTC deployment must retain the contract/EIP-712 ambiguity witness"
        );
        assert!(group.iter().any(|entry| entry.context_kind == CTX_CONTRACT));
        assert!(group.iter().any(|entry| entry.context_kind == CTX_EIP712));
        let domain_separator = group
            .iter()
            .find(|entry| entry.context_kind == CTX_EIP712)
            .map(|entry| Erc7730Ir::parse(&entry.ir_bytes).unwrap().domain_separator)
            .unwrap();

        let address_arg = format!("0x{address_hex}");
        let domain_separator_arg = format!("0x{}", hex::encode(domain_separator));
        let type_hash_arg = format!("0x{type_hash_hex}");
        let trailer = successful_stub_output(run_companion_stub(
            &stub_path,
            &db_path,
            chain_id,
            &address_arg,
            Some("eip712"),
            Some(&domain_separator_arg),
            Some(&type_hash_arg),
        ));
        let verified = verify_erc7730_bundle(&trailer, &result.root)
            .expect("typed companion trailer verifies against pinned root");
        assert_eq!(verified.ir.context_kind, ContextKind::Eip712);
        assert_eq!(verified.ir.chain_id, chain_id);
        assert_eq!(verified.ir.contract, address);
        assert!(
            verified
                .ir
                .format_iter()
                .any(|format| format.is_ok_and(|format| format.type_hash == type_hash)),
            "selected authenticated IR must carry the complete requested type hash"
        );
    }

    // Backward-compatible three-argument/default CLI lookup is deliberately
    // Contract-only; it must not return the adjacent EIP-712 leaf.
    let mainnet_address = "0x8236a87084f8b84306f72007f36f2618a5634494";
    let contract_trailer = successful_stub_output(run_companion_stub(
        &stub_path,
        &db_path,
        1,
        mainnet_address,
        None,
        None,
        None,
    ));
    let verified_contract = verify_erc7730_bundle(&contract_trailer, &result.root)
        .expect("default contract companion trailer verifies");
    let mainnet_address_bytes: [u8; 20] = hex::decode(&mainnet_address[2..])
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(verified_contract.ir.context_kind, ContextKind::Contract);
    assert_eq!(verified_contract.ir.chain_id, 1);
    assert_eq!(verified_contract.ir.contract, mainnet_address_bytes);
    let mainnet_domain_separator = result
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == mainnet_address_bytes
                && entry.context_kind == CTX_EIP712
        })
        .map(|entry| Erc7730Ir::parse(&entry.ir_bytes).unwrap().domain_separator)
        .unwrap();
    let mainnet_domain_arg = format!("0x{}", hex::encode(mainnet_domain_separator));

    // The catalog entry's primary_type_hash is explicitly diagnostic: a
    // multi-format IR may carry other complete hashes. Poison that unauthenticated
    // index hint while leaving the Merkle-authenticated IR/proof untouched; exact
    // lookup must still succeed by parsing the IR format table.
    let mut poisoned_blob = std::fs::read(&db_path).expect("read checked-in companion DB");
    let entry_count = u32::from_le_bytes(poisoned_blob[12..16].try_into().unwrap()) as usize;
    let mut poisoned = false;
    for index in 0..entry_count {
        let base = 32 + index * 72;
        let chain_id = u64::from_le_bytes(poisoned_blob[base..base + 8].try_into().unwrap());
        if chain_id == 1
            && poisoned_blob[base + 8..base + 28] == mainnet_address_bytes
            && poisoned_blob[base + 60] == CTX_EIP712
        {
            assert_eq!(
                &poisoned_blob[base + 28..base + 60],
                &type_hash,
                "control: generated diagnostic hash initially matches the first IR format"
            );
            poisoned_blob[base + 28..base + 60].fill(0xA5);
            poisoned = true;
        }
    }
    assert!(poisoned, "failed to locate the mainnet LBTC EIP-712 entry");
    let temp_dir = tempfile::tempdir().expect("create companion lookup test directory");
    let poisoned_path = temp_dir.path().join("erc7730-diagnostic-hash-poison.bin");
    std::fs::write(&poisoned_path, &poisoned_blob).expect("write poisoned diagnostic DB");
    let type_hash_arg = format!("0x{type_hash_hex}");
    let poisoned_trailer = successful_stub_output(run_companion_stub(
        &stub_path,
        &poisoned_path,
        1,
        mainnet_address,
        Some("eip712"),
        Some(&mainnet_domain_arg),
        Some(&type_hash_arg),
    ));
    let verified_poisoned = verify_erc7730_bundle(&poisoned_trailer, &result.root)
        .expect("entry diagnostic hash is not part of the authenticated leaf/proof");
    assert_eq!(verified_poisoned.ir.context_kind, ContextKind::Eip712);
    assert!(verified_poisoned
        .ir
        .format_iter()
        .any(|format| format.is_ok_and(|format| format.type_hash == type_hash)));

    let wrong_hash = format!("0x{}", "55".repeat(32));
    let rejected = run_companion_stub(
        &stub_path,
        &db_path,
        1,
        mainnet_address,
        Some("eip712"),
        Some(&mainnet_domain_arg),
        Some(&wrong_hash),
    );
    assert!(
        !rejected.status.success(),
        "an absent full EIP-712 type hash must fail rather than select a first deployment"
    );
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("no EIP-712 descriptor"),
        "wrong-hash failure must be an exact lookup miss: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let wrong_domain = format!("0x{}", "aa".repeat(32));
    let rejected_domain = run_companion_stub(
        &stub_path,
        &db_path,
        1,
        mainnet_address,
        Some("eip712"),
        Some(&wrong_domain),
        Some(&type_hash_arg),
    );
    assert!(!rejected_domain.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_domain.stderr).contains("no EIP-712 descriptor"),
        "wrong-domain failure must be an exact lookup miss: {}",
        String::from_utf8_lossy(&rejected_domain.stderr)
    );

    let missing_domain = run_companion_stub(
        &stub_path,
        &db_path,
        1,
        mainnet_address,
        Some("eip712"),
        None,
        Some(&type_hash_arg),
    );
    assert!(!missing_domain.status.success());
    assert!(
        String::from_utf8_lossy(&missing_domain.stderr).contains("--domain-separator is required"),
        "missing-domain failure must be explicit: {}",
        String::from_utf8_lossy(&missing_domain.stderr)
    );

    let missing_hash = run_companion_stub(
        &stub_path,
        &db_path,
        1,
        mainnet_address,
        Some("eip712"),
        Some(&mainnet_domain_arg),
        None,
    );
    assert!(!missing_hash.status.success());
    assert!(
        String::from_utf8_lossy(&missing_hash.stderr).contains("--primary-type-hash is required"),
        "missing-hash failure must be explicit: {}",
        String::from_utf8_lossy(&missing_hash.stderr)
    );

    // The reference must validate every traversed entry before trusting its
    // lookup accelerators. Poison the first entry's reserved padding while
    // leaving the overall catalogue framing intact; lookup must fail closed.
    let mut malformed_blob = std::fs::read(&db_path).unwrap();
    malformed_blob[32 + 61] = 1;
    let malformed_path = temp_dir.path().join("erc7730-malformed-entry.bin");
    std::fs::write(&malformed_path, malformed_blob).unwrap();
    let malformed = run_companion_stub(
        &stub_path,
        &malformed_path,
        1,
        mainnet_address,
        None,
        None,
        None,
    );
    assert!(!malformed.status.success());
    assert!(
        String::from_utf8_lossy(&malformed.stderr).contains("non-zero reserved padding"),
        "malformed-entry failure must name the structural error: {}",
        String::from_utf8_lossy(&malformed.stderr)
    );
}

#[test]
fn companion_stub_finds_secondary_eip712_type_inside_leaf() {
    let root_dir = workspace_root();
    let db_path = root_dir.join("tools/companion-stub/erc7730_db.bin");
    let stub_path = root_dir.join("tools/companion-stub/erc7730_trailer.py");
    let catalogue = build_registry();
    let (chain_id, contract, domain_separator, secondary_type_hash) = catalogue
        .entries
        .iter()
        .find_map(|entry| {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).ok()?;
            if !matches!(ir.context_kind, ContextKind::Eip712) {
                return None;
            }
            let formats: Vec<_> = ir.format_iter().collect::<Result<_, _>>().ok()?;
            Some((
                ir.chain_id,
                ir.contract,
                ir.domain_separator,
                formats.get(1)?.type_hash,
            ))
        })
        .expect("production catalogue has a multi-format EIP-712 leaf");

    let domain_arg = format!("0x{}", hex::encode(domain_separator));
    let type_arg = format!("0x{}", hex::encode(secondary_type_hash));
    let contract_arg = format!("0x{}", hex::encode(contract));
    let out = run_companion_stub(
        &stub_path,
        &db_path,
        chain_id,
        &contract_arg,
        Some("eip712"),
        Some(&domain_arg),
        Some(&type_arg),
    );
    let trailer = successful_stub_output(out);
    let verified = verify_erc7730_bundle(&trailer, &catalogue.root)
        .expect("secondary-type trailer verifies against pinned root");
    assert_eq!(verified.ir.domain_separator, domain_separator);
    assert!(verified
        .ir
        .format_iter()
        .any(|format| { format.is_ok_and(|format| format.type_hash == secondary_type_hash) }));
}

/// Lock the container-field index constants in `pqsigner_erc7730::abi`
/// to the host emitter's keccak-prefix convention. The on-device
/// walker indexes `@.value` / `@.to` / etc. by exactly these `u16`
/// values; any drift breaks every existing `erc7730_db.bin`.
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
                let prog = ir.path_bytes(field.path_off).unwrap_or_else(|e| {
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
                        PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata
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
                        PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata => {
                            panic!(
                                "Root opcode {:?} mid-descent in field {:?}",
                                op, field.label,
                            )
                        }
                        PathOp::FieldIdx => 2,
                        PathOp::ArrayIdx => 4,
                        PathOp::ArraySlice => 8,
                        PathOp::ArrayLast | PathOp::ArrayAll | PathOp::FollowOffset => 0,
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
///   - Every tag is in the known 0x30..=0x48 space.
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
                    // Tag must be in the documented contiguous space through
                    // 0x48 (`PARAM_INTEGER_WIDTH`).
                    assert!(
                        (0x30u8..=0x48).contains(&tag),
                        "unknown TLV tag 0x{:02X} in {:?} field {:?}",
                        tag,
                        ir.contract,
                        field.label
                    );
                    // Per-tag width invariants.
                    match tag {
                        0x31 | 0x44 => assert_eq!(
                            len, 20,
                            "address tag 0x{:02X} must be 20 B in {:?}",
                            tag, field.label
                        ),
                        0x32 => {
                            assert_eq!(len, 32, "PARAM_THRESHOLD must be 32 B in {:?}", field.label)
                        }
                        0x34 | 0x35 | 0x36 | 0x38 | 0x3A | 0x43 | 0x47 => assert_eq!(
                            len, 1,
                            "fixed-1-byte tag 0x{:02X} in {:?}",
                            tag, field.label
                        ),
                        0x48 => {
                            assert_eq!(
                                len, 1,
                                "PARAM_INTEGER_WIDTH must be 1 B in {:?}",
                                field.label
                            );
                            assert!(
                                (1..=32).contains(&body[cursor]),
                                "PARAM_INTEGER_WIDTH must be within 1..=32 in {:?}",
                                field.label
                            );
                        }
                        0x37 => {
                            assert_eq!(len, 2, "PARAM_ENUM_REF must be 2 B in {:?}", field.label)
                        }
                        0x3C => assert_eq!(
                            len, 4,
                            "PARAM_NESTED_SELECTOR must be 4 B in {:?}",
                            field.label
                        ),
                        0x3D => assert!(len > 0, "PARAM_NESTED_CALLEE path must be non-empty"),
                        0x45 => assert_eq!(
                            &body[cursor..cursor + len],
                            pqsigner_erc7730::render::params::NFT_COLLECTION_TO_PATH.as_slice(),
                            "compiler/device NFT collection-path allowlists diverged"
                        ),
                        0x46 => assert!(
                            len > 0,
                            "PARAM_INTERPOLATED_INTENT must be non-empty"
                        ),
                        0x3F => assert!(
                            (1..=255).contains(&len),
                            "PARAM_VISIBILITY must be ≥1 B in {:?}",
                            field.label
                        ),
                        0x42 => assert!(
                            len % pqsigner_erc7730::render::params::NATIVE_CURRENCY_ADDRESS_LEN
                                == 0
                                && (1
                                    ..=pqsigner_erc7730::render::params::MAX_NATIVE_CURRENCY_ADDRESSES)
                                    .contains(
                                        &(len
                                            / pqsigner_erc7730::render::params::NATIVE_CURRENCY_ADDRESS_LEN),
                                    ),
                            "PARAM_NATIVE_CURRENCY must contain 1–{} complete addresses",
                            pqsigner_erc7730::render::params::MAX_NATIVE_CURRENCY_ADDRESSES
                        ),
                        _ => {} // variable-width tags: 0x30, 0x33, 0x39, 0x3B, 0x3E, 0x40, 0x41
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

#[test]
fn unenrolled_address_name_sender_address_drops_only_its_whole_format() {
    let temp = tempfile::tempdir().expect("create senderAddress compiler fixture");
    let policy_path = temp.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n",
    )
    .expect("write synthetic policy");
    let descriptor_path = temp.path().join("calldata-sender-address.json");
    std::fs::write(
        &descriptor_path,
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Synthetic", "contractName": "SenderAddress" },
  "display": { "formats": {
    "route(address recipient,uint256 amount)": {
      "intent": "Route",
      "fields": [
        {
          "path": "recipient",
          "label": "Recipient",
          "format": "addressName",
          "params": {
            "senderAddress": ["0x0000000000000000000000000000000000000001"]
          }
        },
        { "path": "amount", "label": "Amount", "format": "raw" }
      ]
    },
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "label": "To", "format": "addressName" },
        { "path": "amount", "label": "Amount", "format": "raw" }
      ]
    }
  } }
}"#,
    )
    .expect("write synthetic descriptor");

    let policy = load_policy(&policy_path).expect("load synthetic policy");
    let strict_error = try_compile_one(&descriptor_path, &policy, Some(temp.path()))
        .expect_err("strict compilation must reject unenrolled senderAddress authority");
    let enrollment_error = "format `route(address recipient,uint256 amount)` declares senderAddress without an exact descriptor/deployment/selector semantic enrollment";
    assert_eq!(
        strict_error, enrollment_error,
        "the refusal must identify the exact unenrolled authority boundary"
    );

    let (result, skips) = build_db_tolerant(temp.path(), &policy_path, Some(temp.path()))
        .expect("the unrelated safe format survives tolerant compilation");
    assert_eq!(result.leaf_count, 1);
    assert_eq!(result.entries.len(), 1);
    let ir = Erc7730Ir::parse(&result.entries[0].ir_bytes).expect("synthetic IR parses");
    assert_eq!(ir.format_count(), Ok(1));

    let selector = |signature: &str| {
        keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width")
    };
    let unsafe_selector: [u8; 4] = selector("route(address,uint256)");
    let safe_selector: [u8; 4] = selector("transfer(address,uint256)");
    assert!(
        ir.find_format_by_selector(&safe_selector)
            .expect("safe selector lookup")
            .is_some(),
        "the unrelated safe format must survive"
    );
    assert!(
        ir.find_format_by_selector(&unsafe_selector)
            .expect("unsafe selector lookup")
            .is_none(),
        "the senderAddress-bearing format must be dropped as a unit"
    );
    let drop_receipts: Vec<_> = skips
        .iter()
        .filter(|skip| skip.reason.contains("PARTIAL FORMAT DROP"))
        .collect();
    assert_eq!(
        drop_receipts.len(),
        1,
        "one unsafe format, one bound receipt"
    );
    assert!(
        drop_receipts[0]
            .reason
            .contains("route(address recipient,uint256 amount)")
            && drop_receipts[0].reason.contains("senderAddress")
            && drop_receipts[0].reason.contains(enrollment_error),
        "drop receipt must bind the exact format and enrollment failure: {}",
        drop_receipts[0].reason
    );

    let contract = {
        let mut contract = [0u8; 20];
        contract[19] = 1;
        contract
    };
    for selector in [safe_selector, unsafe_selector] {
        assert!(
            result.known_calls.contains(&(1, contract, selector)),
            "every declared selector must remain in exact omission protection"
        );
        assert!(
            known_call_may_contain(&result.known_calls_bloom, 1, &contract, &selector),
            "every declared selector must remain in Bloom omission protection"
        );
    }
}

/// Router02 assigns protocol semantics to sentinel recipient addresses and to
/// zero amounts. Only the two exactly enrolled single-hop selectors may enter
/// trusted IR, and every enrolled sender/word predicate must stay attached to
/// its exact authenticated path. The four broader routes remain absent from the
/// leaf while all six declared selectors stay in exact/Bloom omission defense.
#[test]
fn vendored_uniswap_v3_router02_admits_only_exactly_guarded_single_hop_routes() {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let desc = reg.join("registry/uniswap/calldata-UniswapV3Router02.json");
    let policy = load_policy(&root.join("secure/data/erc7730/policy.toml")).expect("load policy");
    let err = try_compile_one(&desc, &policy, Some(&reg))
        .expect_err("strict compile must refuse the first unsafe C2 format");
    assert!(
        err.contains("params.path") && err.contains("neither rendered"),
        "unexpected strict error: {err}"
    );

    let registry = build_registry();
    let router_entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| entry.source == desc)
        .collect();
    assert_eq!(
        router_entries.len(),
        1,
        "the exact mainnet Router02 deployment must produce one leaf"
    );
    let ir = Erc7730Ir::parse(&router_entries[0].ir_bytes).expect("Router02 IR parses");
    assert_eq!(ir.format_count(), Ok(2));

    let contract_raw =
        hex::decode("68b3465833fb72a70ecdf485e0e4c7bd8665fc45").expect("valid Router02 address");
    let mut contract = [0u8; 20];
    contract.copy_from_slice(&contract_raw);

    let selector_for = |signature: &str| {
        let hash = keccak256(signature.as_bytes());
        <[u8; 4]>::try_from(&hash[..4]).expect("selector width")
    };
    let declared = [
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        "exactInput((bytes,address,uint256,uint256))",
        "exactOutput((bytes,address,uint256,uint256))",
        "swapExactTokensForTokens(uint256,uint256,address[],address)",
        "swapTokensForExactTokens(uint256,uint256,address[],address)",
    ];
    assert_eq!(selector_for(declared[0]), [0x04, 0xe4, 0x5a, 0xaf]);
    assert_eq!(selector_for(declared[1]), [0x50, 0x23, 0xb4, 0xdf]);

    let input_selector = selector_for(declared[0]);
    let output_selector = selector_for(declared[1]);
    let admitted: BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("Router02 format parses").selector)
        .collect();
    assert_eq!(admitted, BTreeSet::from([input_selector, output_selector]));
    for signature in &declared[2..] {
        let selector = selector_for(signature);
        assert!(
            ir.find_format_by_selector(&selector)
                .expect("Router02 format table parses")
                .is_none(),
            "unenrolled/broader route must remain absent from IR: {signature}"
        );
    }

    let mut sender_one = [0u8; 20];
    sender_one[19] = 1;
    let mut address_two_word = [0u8; 32];
    address_two_word[31] = 2;
    let zero_word = [0u8; 32];
    let mut value_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
    value_path.extend_from_slice(&container_field::VALUE.to_be_bytes());
    let structured_path = |member: u8| {
        vec![
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FieldIdx as u8,
            0,
            member,
        ]
    };

    for (selector, exact_input) in [(input_selector, true), (output_selector, false)] {
        let format = ir
            .find_format_by_selector(&selector)
            .expect("Router02 format table parses")
            .expect("enrolled single-hop selector is present");
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("Router02 field parses"))
            .collect();
        assert_eq!(fields.len(), 6, "no synthetic or omitted tuple fields");
        let expected_slots = if exact_input {
            [None, Some(4), Some(5), Some(2), Some(3), Some(6)]
        } else {
            [None, Some(5), Some(4), Some(2), Some(3), Some(6)]
        };
        for (index, (field, slot)) in fields.iter().zip(expected_slots).enumerate() {
            let expected_path = slot.map_or_else(|| value_path.clone(), structured_path);
            assert_eq!(
                ir.path_bytes(field.path_off)
                    .expect("Router02 field path parses"),
                expected_path,
                "wrong authenticated path for field {index} selector 0x{}",
                hex::encode(selector)
            );
        }

        let params: Vec<_> = fields
            .iter()
            .map(|field| parse_params(&ir, field.param_off).expect("Router02 params parse"))
            .collect();
        for (index, parsed) in params.iter().enumerate() {
            if index == 4 {
                assert_eq!(parsed.sender_addresses, Some(sender_one.as_slice()));
                assert!(parsed.sender_address_matches(&sender_one));
            } else {
                assert!(
                    parsed.sender_addresses.is_none(),
                    "sender substitution leaked onto field {index}"
                );
            }
        }

        let assert_guard = |index: usize, mode: u8, expected: &[u8; 32]| {
            let guard = params[index]
                .word_guard
                .unwrap_or_else(|| panic!("field {index} is missing its semantic guard"));
            assert_eq!(guard.mode(), mode, "wrong guard mode on field {index}");
            assert_eq!(
                guard.expected(),
                expected,
                "wrong guard word on field {index}"
            );
        };
        assert_guard(0, WORD_GUARD_EQ, &zero_word);
        assert_guard(4, WORD_GUARD_NE, &address_two_word);
        assert_guard(5, WORD_GUARD_EQ, &zero_word);
        assert!(params[2].word_guard.is_none());
        assert!(params[3].word_guard.is_none());
        if exact_input {
            assert_guard(1, WORD_GUARD_NE, &zero_word);
        } else {
            assert!(params[1].word_guard.is_none());
        }
    }

    for signature in declared {
        let selector = selector_for(signature);
        assert!(
            registry.known_calls.contains(&(1, contract, selector)),
            "every Router02 call must remain in the exact known-call inventory: {signature}"
        );
        assert!(
            known_call_may_contain(&registry.known_calls_bloom, 1, &contract, &selector),
            "every Router02 call must remain in the fail-closed Bloom: {signature}"
        );
    }
}

/// Correct `$ref` resolution must not make endpoint token metadata count as
/// coverage of a complete signed route.
#[test]
fn vendored_paraswap_augustus_v5_endpoint_only_routes_are_omitted() {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let (registry, skips) = build_db_tolerant(&reg.join("registry"), &policy, Some(&reg)).unwrap();
    assert!(
        !registry.entries.iter().any(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-AugustusSwapper-v5.json")
        }),
        "endpoint-only ParaSwap routes must not reach trusted rendering"
    );
    assert!(
        skips.iter().any(|skip| {
            skip.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-AugustusSwapper-v5.json")
                && skip.reason.contains("indexed/sliced tokenPath")
        }),
        "the review must explain that endpoint extraction does not cover the route"
    );
}

// ── Nested-EIP-712 v0x03 anchor emission (Phase 5 v1) ──────────────────────

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Return the shipped IR carrying an exact contract + full EIP-712 type hash.
/// Contract-only lookup is ambiguous because Permit2 hosts multiple schemas.
fn leaf_ir_carrying(
    registry: &Erc7730BuildResult,
    contract: &[u8],
    type_hash: &[u8],
) -> Option<Vec<u8>> {
    registry
        .entries
        .iter()
        .filter(|e| e.contract[..] == contract[..])
        .find(|e| {
            Erc7730Ir::parse(&e.ir_bytes).is_ok_and(|ir| {
                ir.format_iter()
                    .any(|f| f.map(|h| h.type_hash[..] == type_hash[..]).unwrap_or(false))
            })
        })
        .map(|e| e.ir_bytes.clone())
}

#[test]
fn permit2_formats_with_hidden_members_are_not_emitted() {
    let registry = build_registry();
    let permit2 = hex_bytes("000000000022d473030f116ddee9f6b43ac78ba3");
    for type_hash in [
        "f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0",
        "939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106",
    ] {
        let type_hash = hex_bytes(type_hash);
        assert!(
            leaf_ir_carrying(&registry, &permit2, &type_hash).is_none(),
            "Permit2 format with explicit signed-but-unseen members must stay absent"
        );
    }
}

/// Fail-closed corpus guard: the vendored Permit2 descriptor explicitly hides
/// `nonce`. Completeness therefore succeeds, but the independent visibility
/// gate must keep `PermitTransferFrom` out of the shipped DB until the nonce is
/// rendered. An upstream or local edit must not silently re-enable the format.
#[test]
fn vendored_permit2_transfer_from_hidden_nonce_is_not_emitted() {
    let registry = build_registry();
    let permit2 = hex_bytes("000000000022d473030f116ddee9f6b43ac78ba3");
    let ptf = hex_bytes("939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106");
    // The Permit2 contract also hosts UniswapX witness orders, so select by the
    // full type hash rather than a contract-only first match.
    assert!(
        leaf_ir_carrying(&registry, &permit2, &ptf).is_none(),
        "PermitTransferFrom with a signed-but-unseen nonce must not reach the runtime catalogue"
    );
}

/// UniswapX witness-order descriptors hide nonces, deadlines, validation
/// payloads, and price/decay terms. Authenticated nesting binds those words but
/// does not show them, so the full type must remain outside the runtime DB.
#[test]
fn uniswapx_exclusive_dutch_hidden_members_are_not_emitted() {
    let registry = build_registry();
    let permit2 = hex_bytes("000000000022d473030f116ddee9f6b43ac78ba3");
    let type_hash = hex_bytes("2846b6ca8e0ecdbc9ca7696f16bdf77b3baf48504ac14d6a541484ec197e91eb");
    assert!(
        leaf_ir_carrying(&registry, &permit2, &type_hash).is_none(),
        "ExclusiveDutchOrder with signed-but-unseen members must stay absent"
    );
}
