//! Offline provenance checks for externally audited ERC-7730 semantics.
//!
//! These tests deliberately do not contact RPC or explorer services. They
//! authenticate the fixed-block inputs archived under
//! tests/erc7730-semantic-evidence and bind them back to the production
//! descriptor deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::{cross_check_contract, BindingError};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, PathOp, Visibility};
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn stakewise_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/stakewise-claim-exited-assets")
}

fn lido_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lido-wsteth-permit")
}

fn lido_queue_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lido-withdrawal-queue")
}

fn lido_staking_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lido-staking")
}

fn aave_permit_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/aave-pq-permit-compatibility")
}

fn uniswap_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/uniswap-router02-single-hop")
}

fn quickswap_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/quickswap-router02-remove-liquidity")
}

fn weth9_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/weth9-deposit")
}

fn allowance_threshold_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/allowance-threshold-honesty")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn decode_hex_text(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid hex evidence")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex_text(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(haystack: &str, fragments: &[&str]) {
    let mut remainder = haystack;
    for fragment in fragments {
        let offset = remainder
            .find(fragment)
            .unwrap_or_else(|| panic!("missing ordered source fragment: {fragment}"));
        remainder = &remainder[offset + fragment.len()..];
    }
}

fn rpc_response(receipt: &Value, id: u64) -> &Value {
    receipt
        .as_array()
        .expect("RPC receipt is an array")
        .iter()
        .find(|response| response["id"].as_u64() == Some(id))
        .unwrap_or_else(|| panic!("RPC receipt is missing response id {id}"))
}

fn decode_abi_word_address(text: &str) -> String {
    let word = decode_hex_text(text);
    assert_eq!(word.len(), 32, "ABI address result is one word");
    assert_eq!(&word[..12], &[0u8; 12], "ABI address padding changed");
    format!("0x{}", hex::encode(&word[12..]))
}

fn decode_abi_word_u128(text: &str) -> u128 {
    let word = decode_hex_text(text);
    assert_eq!(word.len(), 32, "ABI integer result is one word");
    assert_eq!(&word[..16], &[0u8; 16], "test value exceeds u128");
    u128::from_be_bytes(word[16..].try_into().expect("u128 word width"))
}

fn normalized_solidity_function(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing Solidity function signature: {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing Solidity function body: {signature}"));
    let mut depth = 0usize;
    let mut end = None;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced Solidity braces");
                if depth == 0 {
                    end = Some(open + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let definition = &source[start..end.expect("complete Solidity function body")];
    let code_without_line_comments = definition
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    normalized_whitespace(&code_without_line_comments)
}

fn decode_abi_string_result(text: &str) -> String {
    let bytes = decode_hex_text(text);
    assert!(bytes.len() >= 64, "ABI string result is truncated");
    assert_eq!(&bytes[..31], &[0u8; 31]);
    assert_eq!(bytes[31], 32, "ABI string data offset changed");
    assert_eq!(&bytes[32..63], &[0u8; 31]);
    let length = bytes[63] as usize;
    assert!(
        64 + length <= bytes.len(),
        "ABI string payload is truncated"
    );
    String::from_utf8(bytes[64..64 + length].to_vec()).expect("ABI string is UTF-8")
}

#[test]
fn aave_v3_vrs_permit_routes_cannot_carry_pqsmartwallet_authorization() {
    let root = aave_permit_evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&manifest["revision_sources"], "revision_11_commit"),
        "fd1fbd9150426ca8ace9cee45b4acf912ae84f5b"
    );
    assert_eq!(
        required_str(&manifest["revision_sources"], "revision_10_commit"),
        "e8feb287e4bc492c62a5c1c19086262c6e223b37"
    );

    let upstream = manifest["upstream"]
        .as_array()
        .expect("Aave upstream evidence is an array");
    assert_eq!(upstream.len(), 3);
    for artifact in upstream {
        assert_eq!(
            required_str(artifact, "repository"),
            "https://github.com/aave-dao/aave-v3-origin"
        );
        assert_eq!(
            required_str(artifact, "commit"),
            "fd1fbd9150426ca8ace9cee45b4acf912ae84f5b"
        );
        let archive = root.join(required_str(artifact, "archive_file"));
        let bytes = fs::read(&archive)
            .unwrap_or_else(|error| panic!("read {}: {error}", archive.display()));
        assert_eq!(
            sha256_hex(&bytes),
            required_str(artifact, "archive_file_sha256"),
            "Aave source excerpt drifted: {}",
            archive.display()
        );
        assert_eq!(required_str(artifact, "full_file_sha256").len(), 64);
    }

    let pool = normalized_whitespace(
        &fs::read_to_string(root.join("source/Pool.permit.excerpt.sol"))
            .expect("read Aave Pool excerpt"),
    );
    assert_fragments_in_order(
        &pool,
        &[
            "function supply(",
            "user: _msgSender()",
            "function supplyWithPermit(",
            "IERC20WithPermit(asset).permit( _msgSender(), address(this), amount, deadline, permitV, permitR, permitS ) {} catch {}",
            "user: _msgSender()",
            "function repay(",
            "user: _msgSender()",
            "function repayWithPermit(",
            "IERC20WithPermit(asset).permit( _msgSender(), address(this), amount, deadline, permitV, permitR, permitS ) {} catch {}",
            "user: _msgSender()",
        ],
    );
    assert_eq!(
        pool.matches("supplierEModeCategory: _usersEModeCategory[onBehalfOf]")
            .count(),
        2,
        "permit and ordinary supply must share the same continuation"
    );
    assert_eq!(
        pool.matches("useATokens: false").count(),
        2,
        "permit and ordinary repay must share the same continuation"
    );

    let gateway = normalized_whitespace(
        &fs::read_to_string(root.join("source/WrappedTokenGatewayV3.permit.excerpt.sol"))
            .expect("read Aave gateway excerpt"),
    );
    assert_fragments_in_order(
        &gateway,
        &[
            "function withdrawETH(",
            "aWETH.transferFrom(msg.sender, address(this), amountToWithdraw)",
            "function withdrawETHWithPermit(",
            "aWETH.permit(msg.sender, address(this), amount, deadline, permitV, permitR, permitS) {} catch {}",
            "aWETH.transferFrom(msg.sender, address(this), amountToWithdraw)",
        ],
    );

    let atoken = normalized_whitespace(
        &fs::read_to_string(root.join("source/AToken.permit.excerpt.sol"))
            .expect("read Aave aToken excerpt"),
    );
    assert!(atoken
        .contains("require(owner == ECDSA.recover(digest, v, r, s), Errors.InvalidSignature())"));

    let workspace = workspace_root();
    let wallet = fs::read_to_string(workspace.join("contracts/smart-wallet/src/PQSmartWallet.sol"))
        .expect("read PQSmartWallet source");
    assert!(wallet.contains("target.call{value: value}(data)"));
    assert!(wallet.contains("targets[i].call{value: values[i]}(datas[i])"));
    assert!(wallet.contains("if (signature.length != 96 + paddedInner) return false;"));
    assert!(wallet.contains("if (innerLen != C10_SIG_LEN) return false;"));

    let constants = fs::read_to_string(
        workspace.join("contracts/smart-wallet/src/generated/PqsignerProto.sol"),
    )
    .expect("read generated signature constants");
    assert!(constants.contains("uint256 internal constant C10_SIG_LEN = 4008;"));
    assert!(constants.contains("uint256 internal constant SIG_WRAPPER_LEN = 4128;"));
    assert_eq!(
        manifest["pqsmartwallet"]["c10_signature_bytes"].as_u64(),
        Some(4008)
    );
    assert_eq!(
        manifest["pqsmartwallet"]["signature_wrapper_bytes"].as_u64(),
        Some(4128)
    );
}

fn eip712_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    contract: &[u8; 20],
) -> [u8; 32] {
    let mut encoded = [0u8; 160];
    encoded[..32].copy_from_slice(&keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    encoded[32..64].copy_from_slice(&keccak256(name.as_bytes()));
    encoded[64..96].copy_from_slice(&keccak256(version.as_bytes()));
    encoded[120..128].copy_from_slice(&chain_id.to_be_bytes());
    encoded[140..160].copy_from_slice(contract);
    keccak256(&encoded)
}

#[test]
fn weth9_deposit_and_withdraw_descriptor_and_generated_ir_bind_exact_signed_amounts() {
    let root = workspace_root();
    let descriptor_path =
        root.join("secure/data/erc7730-registry/registry/weth/calldata-weth.json");
    let descriptor_bytes = fs::read(&descriptor_path).expect("read vendored WETH descriptor");
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse vendored WETH descriptor");

    let expected_deployments = BTreeMap::from([
        (1u64, "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_owned()),
        (
            11_155_111u64,
            "fff9976782d46cc05630d1f6ebab18b2324d6b14".to_owned(),
        ),
    ]);
    let actual_deployments: BTreeMap<_, _> = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("WETH descriptor deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"]
                    .as_u64()
                    .expect("WETH deployment chain"),
                deployment["address"]
                    .as_str()
                    .expect("WETH deployment address")
                    .trim_start_matches("0x")
                    .to_ascii_lowercase(),
            )
        })
        .collect();
    assert_eq!(actual_deployments, expected_deployments);

    let descriptor_formats = descriptor["display"]["formats"]
        .as_object()
        .expect("WETH descriptor formats");
    assert_eq!(
        descriptor_formats
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["deposit()", "withdraw(uint256 wad)"])
    );

    let deposit_descriptor = &descriptor_formats["deposit()"];
    assert_eq!(deposit_descriptor["intent"].as_str(), Some("Wrap"));
    let deposit_fields = deposit_descriptor["fields"]
        .as_array()
        .expect("WETH deposit fields");
    assert_eq!(deposit_fields.len(), 1);
    assert_eq!(deposit_fields[0]["label"].as_str(), Some("Amount"));
    assert_eq!(deposit_fields[0]["path"].as_str(), Some("@.value"));
    assert_eq!(deposit_fields[0]["format"].as_str(), Some("amount"));
    assert!(
        deposit_fields[0].get("params").is_none(),
        "native value semantics must come from the authenticated @.value path, not host metadata"
    );

    let withdraw_descriptor = &descriptor_formats["withdraw(uint256 wad)"];
    assert_eq!(withdraw_descriptor["intent"].as_str(), Some("Unwrap"));
    let withdraw_fields = withdraw_descriptor["fields"]
        .as_array()
        .expect("WETH withdraw fields");
    assert_eq!(withdraw_fields.len(), 1);
    assert_eq!(withdraw_fields[0]["label"].as_str(), Some("Amount"));
    assert_eq!(withdraw_fields[0]["path"].as_str(), Some("wad"));
    assert_eq!(withdraw_fields[0]["format"].as_str(), Some("tokenAmount"));
    assert_eq!(withdraw_fields[0]["visible"].as_str(), Some("always"));
    assert_eq!(
        withdraw_fields[0]["params"]["tokenPath"].as_str(),
        Some("@.to"),
        "withdraw amount identity must be the authenticated exact target contract"
    );

    let deposit_signature = "deposit()";
    let deposit_selector: [u8; 4] = keccak256(deposit_signature.as_bytes())[..4]
        .try_into()
        .expect("deposit selector width");
    assert_eq!(deposit_selector, [0xd0, 0xe3, 0x0d, 0xb0]);
    let withdraw_signature = "withdraw(uint256)";
    let withdraw_selector: [u8; 4] = keccak256(withdraw_signature.as_bytes())[..4]
        .try_into()
        .expect("withdraw selector width");
    assert_eq!(withdraw_selector, [0x2e, 0x1a, 0x7d, 0x4d]);

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let registry_root = root.join("secure/data/erc7730-registry");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-weth.json")
        })
        .collect();
    assert_eq!(entries.len(), 2, "both WETH deployments must emit leaves");

    let expected_descriptor_hash: [u8; 32] =
        decode_hex_text("e0e7cdedb3078b0ae2542baf084a519a0897a295ae75bf92fc18cfb89f2293e2")
            .try_into()
            .expect("descriptor hash width");
    for entry in entries {
        assert_eq!(
            expected_deployments.get(&entry.chain_id),
            Some(&hex::encode(entry.contract)),
            "generated WETH leaf deployment drifted"
        );
        assert_eq!(entry.descriptor_hash, expected_descriptor_hash);
        assert_eq!(entry.ir_bytes.len(), 218, "WETH IR wire length drifted");

        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse generated WETH IR");
        assert_eq!(
            cross_check_contract(&ir, entry.chain_id, &entry.contract),
            Ok(())
        );
        assert_eq!(ir.owner, b"WETH");
        assert_eq!(ir.contract_name, b"WETH");
        assert_eq!(ir.format_count(), Ok(2));

        let deposit = ir
            .find_format_by_selector(&deposit_selector)
            .expect("WETH format table parses")
            .expect("deposit remains admitted");
        assert_eq!(deposit.selector, deposit_selector);
        assert_eq!(deposit.intent, b"Wrap");
        assert_eq!(deposit.static_head_words, 0);
        assert_eq!(deposit.nested_descent_count, 0);
        let fields: Vec<_> = deposit
            .fields()
            .map(|field| field.expect("WETH deposit field parses"))
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, b"Amount");
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::Amount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("WETH value path parses"),
            [0x11, 0x20, 0x81, 0xaf],
            "generated IR must read the signed transaction envelope's exact value word"
        );
        let params = parse_params(&ir, fields[0].param_off).expect("WETH amount params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(params.integer_width_bytes, Some(32));
        assert!(params.token.is_none());
        assert!(params.token_path.is_none());

        let withdraw = ir
            .find_format_by_selector(&withdraw_selector)
            .expect("WETH format table parses")
            .expect("withdraw remains admitted");
        assert_eq!(withdraw.selector, withdraw_selector);
        assert_eq!(withdraw.intent, b"Unwrap");
        assert_eq!(withdraw.static_head_words, 1);
        assert_eq!(withdraw.nested_descent_count, 0);
        let fields: Vec<_> = withdraw
            .fields()
            .map(|field| field.expect("WETH withdraw field parses"))
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label, b"Amount");
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::TokenAmount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("WETH withdraw amount path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
            "withdraw must display the exact first uint256 calldata word"
        );
        let params =
            parse_params(&ir, fields[0].param_off).expect("WETH token amount params parse");
        assert_eq!(params.visibility, Visibility::Always);
        assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(params.integer_width_bytes, Some(32));
        assert!(params.token.is_none());
        let mut target_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
        target_path.extend_from_slice(&container_field::TO.to_be_bytes());
        assert_eq!(params.token_path, Some(target_path.as_slice()));

        for selector in [deposit_selector, withdraw_selector] {
            assert!(
                registry
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "each admitted WETH route must be an exact known-call tuple"
            );
        }
    }
}

#[test]
fn weth9_fixed_block_evidence_binds_source_abi_runtime_and_rpc_agreement() {
    let evidence = weth9_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let routes = manifest["routes"].as_array().expect("WETH9 routes");
    assert_eq!(routes.len(), 2);
    let route_by_key: BTreeMap<_, _> = routes
        .iter()
        .map(|route| (required_str(route, "key"), route))
        .collect();
    assert_eq!(
        route_by_key.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from(["deposit", "withdraw"])
    );
    let deposit_route = route_by_key["deposit"];
    assert_eq!(
        required_str(deposit_route, "descriptor_signature"),
        "deposit()"
    );
    assert_eq!(
        required_str(deposit_route, "canonical_signature"),
        "deposit()"
    );
    assert_eq!(required_str(deposit_route, "selector"), "0xd0e30db0");
    assert_eq!(required_str(deposit_route, "state_mutability"), "payable");
    assert_eq!(
        required_str(&deposit_route["displayed_signed_facts"][0], "path"),
        "@.value"
    );
    assert_eq!(
        required_str(deposit_route, "successful_effect"),
        "Credits balanceOf[msg.sender] by exactly msg.value and emits Deposit(msg.sender, msg.value)."
    );

    let withdraw_route = route_by_key["withdraw"];
    assert_eq!(
        required_str(withdraw_route, "descriptor_signature"),
        "withdraw(uint256 wad)"
    );
    assert_eq!(
        required_str(withdraw_route, "canonical_signature"),
        "withdraw(uint256)"
    );
    assert_eq!(required_str(withdraw_route, "selector"), "0x2e1a7d4d");
    assert_eq!(
        required_str(withdraw_route, "state_mutability"),
        "nonpayable"
    );
    let withdraw_fact = &withdraw_route["displayed_signed_facts"][0];
    assert_eq!(required_str(withdraw_fact, "path"), "wad");
    assert_eq!(required_str(withdraw_fact, "format"), "tokenAmount");
    assert_eq!(required_str(withdraw_fact, "token_path"), "@.to");
    assert_eq!(required_str(withdraw_fact, "visibility"), "always");
    assert_eq!(
        required_str(withdraw_route, "successful_effect"),
        "Requires balanceOf[msg.sender] >= wad, subtracts exactly wad from that balance, transfers exactly wad wei of native ETH to msg.sender, and emits Withdrawal(msg.sender, wad)."
    );
    for route in routes {
        let signature = required_str(route, "canonical_signature");
        assert_eq!(
            format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])),
            required_str(route, "selector"),
            "WETH9 route selector drifted"
        );
    }

    let receipt_spec = &manifest["rpc_receipt"];
    let receipt_path = evidence.join(required_str(receipt_spec, "file"));
    let receipt_bytes = fs::read(&receipt_path).expect("read WETH9 RPC receipt");
    assert_eq!(
        sha256_hex(&receipt_bytes),
        required_str(receipt_spec, "file_sha256")
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("parse WETH9 RPC receipt");
    assert_eq!(receipt["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&receipt, "canonical_signature"),
        required_str(deposit_route, "canonical_signature"),
        "the immutable receipt retains its original deposit capture label"
    );
    assert_eq!(
        required_str(&receipt, "selector"),
        required_str(deposit_route, "selector")
    );
    assert!(required_str(receipt_spec, "capture_label_boundary")
        .contains("complete-runtime, proxy-slot, and metadata observations"));

    let receipt_networks = receipt["networks"]
        .as_array()
        .expect("WETH9 receipt networks");
    let deployments = manifest["deployments"]
        .as_array()
        .expect("WETH9 manifest deployments");
    assert_eq!(deployments.len(), 2);
    assert_eq!(receipt_networks.len(), 2);
    let mut runtimes = BTreeMap::<u64, Vec<u8>>::new();
    for deployment in deployments {
        let chain_id = deployment["chain_id"].as_u64().expect("WETH9 chain ID");
        let address = required_str(deployment, "address");
        let runtime_spec = &deployment["runtime"];
        let runtime_file = required_str(runtime_spec, "file");
        let runtime_artifact = fs::read(evidence.join(runtime_file)).expect("read WETH9 runtime");
        assert_eq!(
            sha256_hex(&runtime_artifact),
            required_str(runtime_spec, "file_sha256")
        );
        let runtime = read_hex(&evidence.join(runtime_file));
        assert_eq!(
            u64::try_from(runtime.len()).expect("runtime length fits u64"),
            runtime_spec["bytes"].as_u64().expect("runtime byte count")
        );
        assert_eq!(
            keccak_hex(&runtime),
            required_str(runtime_spec, "keccak256")
        );
        runtimes.insert(chain_id, runtime);

        let network = receipt_networks
            .iter()
            .find(|network| network["chain_id"].as_u64() == Some(chain_id))
            .expect("receipt owns each WETH9 deployment");
        assert_eq!(required_str(network, "address"), address);
        assert_eq!(
            required_str(network, "runtime_file"),
            required_str(runtime_spec, "file")
        );
        assert_eq!(network["endpoints"], deployment["rpc_endpoints"]);

        let observations = network["observations"]
            .as_array()
            .expect("WETH9 RPC observations");
        assert_eq!(observations.len(), 2, "two independent RPC observations");
        assert_ne!(
            required_str(&observations[0], "endpoint"),
            required_str(&observations[1], "endpoint")
        );
        assert_eq!(observations[0]["block"], observations[1]["block"]);
        assert_eq!(observations[0]["code"], observations[1]["code"]);
        assert_eq!(
            observations[0]["proxy_slots"],
            observations[1]["proxy_slots"]
        );
        assert_eq!(observations[0]["calls"], observations[1]["calls"]);

        for observation in observations {
            let block = &observation["block"];
            let expected_block = &deployment["evidence_block"];
            for key in ["number", "number_hex", "hash", "state_root", "timestamp"] {
                assert_eq!(
                    block[key], expected_block[key],
                    "fixed block drifted: {key}"
                );
            }
            assert_eq!(
                required_str(&observation["code"], "result_file"),
                runtime_file
            );
            assert_eq!(observation["code"]["bytes"], runtime_spec["bytes"]);
            assert_eq!(
                required_str(&observation["code"], "keccak256"),
                required_str(runtime_spec, "keccak256")
            );
            for slot in ["implementation", "admin", "beacon"] {
                assert_eq!(
                    required_str(&observation["proxy_slots"][slot], "result"),
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                );
            }
            assert_eq!(
                observation["calls"]["name"]["decoded"].as_str(),
                Some("Wrapped Ether")
            );
            assert_eq!(
                observation["calls"]["symbol"]["decoded"].as_str(),
                Some("WETH")
            );
            assert_eq!(
                observation["calls"]["decimals"]["decoded"].as_u64(),
                Some(18)
            );
        }
    }

    let mainnet = runtimes.get(&1).expect("mainnet WETH9 runtime");
    let sepolia = runtimes.get(&11_155_111).expect("Sepolia WETH9 runtime");
    assert_eq!(mainnet.len(), 3_124);
    assert_eq!(mainnet.len(), sepolia.len());
    let relationship = &manifest["runtime_relationship"];
    let prefix_len = relationship["executable_prefix_bytes"]
        .as_u64()
        .expect("executable prefix length") as usize;
    assert_eq!(prefix_len, 3_081);
    assert_eq!(&mainnet[..prefix_len], &sepolia[..prefix_len]);
    assert_eq!(
        keccak_hex(&mainnet[..prefix_len]),
        required_str(relationship, "executable_prefix_keccak256")
    );
    let mut pc = 0usize;
    while pc < prefix_len {
        let opcode = mainnet[pc];
        assert!(
            !matches!(opcode, 0xf2 | 0xf4 | 0xff),
            "verified WETH9 executable contains proxy/destruction opcode 0x{opcode:02x} at {pc}"
        );
        pc += 1;
        if (0x60..=0x7f).contains(&opcode) {
            pc += usize::from(opcode - 0x5f);
        }
    }
    assert_eq!(
        pc, prefix_len,
        "executable prefix ends on an opcode boundary"
    );
    let differing: Vec<_> = mainnet
        .iter()
        .zip(sepolia)
        .enumerate()
        .filter_map(|(index, (left, right))| (left != right).then_some(index))
        .collect();
    assert_eq!(differing, (3_090usize..=3_121).collect::<Vec<_>>());
    assert_eq!(relationship["differing_bytes"].as_u64(), Some(32));

    let source_specs = [
        &manifest["verified_source"]["official_upstream"],
        &manifest["verified_source"]["ethereum_mainnet"],
        &manifest["verified_source"]["ethereum_sepolia"],
    ];
    let mut sources = Vec::new();
    for spec in source_specs {
        let path = evidence.join(required_str(spec, "archived_file"));
        let bytes = fs::read(&path).expect("read archived WETH9 source");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(spec, "archived_file_sha256")
        );
        let source = String::from_utf8(bytes).expect("WETH9 source is UTF-8");
        let normalized = normalized_whitespace(&source);
        assert_fragments_in_order(
            &normalized,
            &[
                "function deposit() public payable {",
                "balanceOf[msg.sender] += msg.value;",
                "Deposit(msg.sender, msg.value);",
                "}",
                "function withdraw(uint wad) public {",
                "require(balanceOf[msg.sender] >= wad);",
                "balanceOf[msg.sender] -= wad;",
                "msg.sender.transfer(wad);",
                "Withdrawal(msg.sender, wad);",
                "}",
            ],
        );
        assert_eq!(
            normalized_solidity_function(&source, "function withdraw(uint wad) public"),
            "function withdraw(uint wad) public { require(balanceOf[msg.sender] >= wad); balanceOf[msg.sender] -= wad; msg.sender.transfer(wad); Withdrawal(msg.sender, wad); }",
            "the pinned withdrawal must debit, pay, and report the same exact signed wad"
        );
        sources.push(source);
    }
    assert_eq!(
        sources[0].replace("contract WETH9_", "contract WETH9"),
        sources[1],
        "official and mainnet-verified sources differ only in the contract name"
    );
    assert_eq!(
        sources[2]
            .strip_prefix("/**\n *Submitted for verification at Etherscan.io on 2017-12-12\n*/\n\n")
            .expect("Sepolia verification header is pinned"),
        sources[1]
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read WETH9 ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse WETH9 ABI");
    assert_eq!(abi.as_array().map(Vec::len), Some(16));
    let deposit = abi
        .as_array()
        .expect("WETH9 ABI array")
        .iter()
        .find(|entry| {
            entry["type"].as_str() == Some("function") && entry["name"].as_str() == Some("deposit")
        })
        .expect("deposit ABI entry");
    assert_eq!(deposit["stateMutability"].as_str(), Some("payable"));
    assert_eq!(deposit["inputs"].as_array().map(Vec::len), Some(0));
    assert_eq!(deposit["outputs"].as_array().map(Vec::len), Some(0));
    let withdraw = abi
        .as_array()
        .expect("WETH9 ABI array")
        .iter()
        .find(|entry| {
            entry["type"].as_str() == Some("function") && entry["name"].as_str() == Some("withdraw")
        })
        .expect("withdraw ABI entry");
    assert_eq!(withdraw["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(withdraw["payable"].as_bool(), Some(false));
    let withdraw_inputs = withdraw["inputs"].as_array().expect("withdraw ABI inputs");
    assert_eq!(withdraw_inputs.len(), 1);
    assert_eq!(withdraw_inputs[0]["name"].as_str(), Some("wad"));
    assert_eq!(withdraw_inputs[0]["type"].as_str(), Some("uint256"));
    assert_eq!(withdraw["outputs"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        format!(
            "{}({})",
            withdraw["name"].as_str().expect("withdraw ABI name"),
            withdraw_inputs[0]["type"]
                .as_str()
                .expect("withdraw ABI input type")
        ),
        required_str(withdraw_route, "canonical_signature")
    );

    let mainnet_record = &manifest["deployments"][0]["official_deployment_record"];
    let deployment_bytes = fs::read(evidence.join(required_str(mainnet_record, "archived_file")))
        .expect("read canonical WETH deployment record");
    assert_eq!(
        sha256_hex(&deployment_bytes),
        required_str(mainnet_record, "archived_file_sha256")
    );
    let deployment_record: Value =
        serde_json::from_slice(&deployment_bytes).expect("parse canonical WETH deployments");
    assert_eq!(
        deployment_record["WETH9"]["1"]["address"].as_str(),
        Some("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    );
    assert_eq!(
        deployment_record["WETH9"]["1"]["transactionHash"].as_str(),
        Some(required_str(mainnet_record, "transaction_hash"))
    );
    assert!(
        required_str(&manifest["direct_contract_classification"], "boundary")
            .contains("zero-slot checks alone would not exclude every bespoke proxy")
    );
    assert_eq!(
        manifest["direct_contract_classification"]["classification"].as_str(),
        Some("direct")
    );
}

#[test]
fn lido_staking_fixed_block_evidence_binds_proxy_runtime_and_rpc_agreement() {
    let root = workspace_root();
    let evidence = lido_staking_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));

    for upstream in [
        &manifest["upstream"]["lido_core"],
        &manifest["upstream"]["si_lidity"],
    ] {
        for key in ["deployment_record", "source"] {
            if let Some(spec) = upstream.get(key) {
                let archive_file = required_str(spec, "archive_file");
                let bytes = fs::read(evidence.join(archive_file))
                    .unwrap_or_else(|error| panic!("read {archive_file}: {error}"));
                assert_eq!(
                    sha256_hex(&bytes),
                    required_str(spec, "sha256"),
                    "official Lido artifact drifted: {archive_file}"
                );
            }
        }
    }

    let core_deployment = read_json(&evidence.join("deployment/deployed-mainnet.json"));
    let core_lido = &core_deployment["app:lido"];
    let steth = &manifest["deployment"]["steth"];
    assert!(core_lido["proxy"]["address"]
        .as_str()
        .expect("official stETH proxy")
        .eq_ignore_ascii_case(required_str(steth, "proxy_address")));
    assert!(core_lido["implementation"]["address"]
        .as_str()
        .expect("official stETH implementation")
        .eq_ignore_ascii_case(required_str(steth, "implementation_address")));
    assert_eq!(
        core_lido["implementation"]["contract"].as_str(),
        Some("contracts/0.4.24/Lido.sol")
    );
    assert_eq!(
        core_lido["aragonApp"]["id"].as_str(),
        Some(required_str(steth, "app_id"))
    );

    let si_deployment = fs::read_to_string(evidence.join("deployment/si-lidity-mainnet.md"))
        .expect("read official referral-staker deployment record");
    assert!(si_deployment.contains("0xa88f0329C2c4ce51ba3fc619BBf44efE7120Dd0d"));
    assert!(!si_deployment.contains("0xeC9d1B39594cde226CB3CFdf703C657983517EeE"));

    let script_spec = &manifest["rpc"]["collection_script"];
    let script_bytes = fs::read(evidence.join(required_str(script_spec, "file")))
        .expect("read Lido RPC collection script");
    assert_eq!(
        sha256_hex(&script_bytes),
        required_str(script_spec, "sha256")
    );
    let script = String::from_utf8(script_bytes).expect("collection script is UTF-8");
    assert_fragments_in_order(
        &script,
        &[
            "block=0x1862773",
            "steth=0xae7ab96520de3a18e5e111b5eaab095312d7fe84",
            "implementation=0x6ca84080381e43938476814be61b779a8bb6a600",
            "staker=0xa88f0329c2c4ce51ba3fc619bbf44efe7120dd0d",
            "collect_endpoint drpc https://eth.drpc.org",
            "collect_endpoint mevblocker https://rpc.mevblocker.io",
        ],
    );

    let receipt_specs = manifest["rpc"]["receipts"]
        .as_array()
        .expect("two Lido RPC receipts");
    assert_eq!(receipt_specs.len(), 2);
    assert_ne!(
        required_str(&receipt_specs[0], "endpoint"),
        required_str(&receipt_specs[1], "endpoint")
    );
    let mut receipts = Vec::new();
    for spec in receipt_specs {
        let bytes = fs::read(evidence.join(required_str(spec, "file")))
            .expect("read endpoint-specific Lido RPC receipt");
        assert_eq!(sha256_hex(&bytes), required_str(spec, "sha256"));
        let receipt: Value = serde_json::from_slice(&bytes).expect("parse Lido RPC receipt");
        let responses = receipt.as_array().expect("RPC receipt array");
        assert_eq!(responses.len(), 15);
        assert_eq!(
            responses
                .iter()
                .map(|response| response["id"].as_u64().expect("numeric RPC id"))
                .collect::<BTreeSet<_>>(),
            (1u64..=15).collect()
        );
        for response in responses {
            assert_eq!(response["jsonrpc"].as_str(), Some("2.0"));
            assert!(response.get("error").is_none());
            assert!(response.get("result").is_some());
        }
        receipts.push(receipt);
    }
    for id in 1u64..=15 {
        assert_eq!(
            rpc_response(&receipts[0], id)["result"],
            rpc_response(&receipts[1], id)["result"],
            "independent RPC results disagree for response id {id}"
        );
    }

    assert_eq!(
        rpc_response(&receipts[0], 1)["result"].as_str(),
        Some("0x1")
    );
    let block = &rpc_response(&receipts[0], 2)["result"];
    let fixed_block = &manifest["deployment"]["fixed_block"];
    assert_eq!(block["number"], fixed_block["number_hex"]);
    assert_eq!(block["hash"], fixed_block["hash"]);
    assert_eq!(block["stateRoot"], fixed_block["state_root"]);
    assert_eq!(block["timestamp"].as_str(), Some("0x6a5d3313"));

    let runtime_bindings = [
        ("steth_proxy", 3u64),
        ("lido_implementation", 4u64),
        ("referral_staker", 5u64),
    ];
    let mut runtimes = BTreeMap::<String, Vec<u8>>::new();
    for (name, id) in runtime_bindings {
        let spec = &manifest["runtime_artifacts"][name];
        let artifact = fs::read(evidence.join(required_str(spec, "file")))
            .unwrap_or_else(|error| panic!("read {name} runtime: {error}"));
        assert_eq!(sha256_hex(&artifact), required_str(spec, "file_sha256"));
        let runtime = decode_hex_text(
            &String::from_utf8(artifact).unwrap_or_else(|_| panic!("{name} runtime is hex text")),
        );
        assert_eq!(
            runtime.len() as u64,
            spec["bytes"].as_u64().expect("runtime bytes")
        );
        assert_eq!(keccak_hex(&runtime), required_str(spec, "keccak256"));
        assert_eq!(
            runtime,
            decode_hex_text(
                rpc_response(&receipts[0], id)["result"]
                    .as_str()
                    .expect("RPC code result")
            ),
            "archived {name} runtime differs from the raw RPC result"
        );
        runtimes.insert(name.to_owned(), runtime);
    }

    assert_eq!(
        decode_abi_word_address(
            rpc_response(&receipts[0], 6)["result"]
                .as_str()
                .expect("implementation result")
        ),
        required_str(steth, "implementation_address")
    );
    assert_eq!(
        decode_abi_word_u128(
            rpc_response(&receipts[0], 7)["result"]
                .as_str()
                .expect("proxy type result")
        ),
        steth["proxy_type"].as_u64().expect("proxy type") as u128
    );
    assert_eq!(
        decode_abi_word_address(
            rpc_response(&receipts[0], 8)["result"]
                .as_str()
                .expect("kernel result")
        ),
        required_str(steth, "kernel")
    );
    assert_eq!(
        rpc_response(&receipts[0], 9)["result"].as_str(),
        Some(required_str(steth, "app_id"))
    );

    let staker = &manifest["deployment"]["referral_staker"];
    assert_eq!(
        decode_abi_word_address(
            rpc_response(&receipts[0], 10)["result"]
                .as_str()
                .expect("staker stETH result")
        ),
        required_str(staker, "steth")
    );
    assert_eq!(
        decode_abi_word_address(
            rpc_response(&receipts[0], 11)["result"]
                .as_str()
                .expect("staker wstETH result")
        ),
        required_str(staker, "wsteth")
    );

    for (key, id) in [
        ("shares_for_one_eth", 12u64),
        ("pooled_eth_for_one_share", 13u64),
        ("wsteth_for_one_steth", 14u64),
        ("steth_for_one_wsteth", 15u64),
    ] {
        assert_eq!(
            decode_abi_word_u128(
                rpc_response(&receipts[0], id)["result"]
                    .as_str()
                    .expect("rate result")
            ),
            required_str(&manifest["fixed_block_outputs"], key)
                .parse::<u128>()
                .expect("manifest rate is u128"),
            "fixed-block rate receipt drifted: {key}"
        );
    }

    let staker_runtime = runtimes
        .get("referral_staker")
        .expect("referral-staker runtime");
    let staker_spec = &manifest["runtime_artifacts"]["referral_staker"];
    let prefix_len = staker_spec["executable_prefix_bytes"]
        .as_u64()
        .expect("executable prefix bytes") as usize;
    let metadata_len = staker_spec["cbor_metadata_bytes"]
        .as_u64()
        .expect("CBOR metadata bytes") as usize;
    assert_eq!(staker_runtime.len(), prefix_len + metadata_len + 2);
    assert_eq!(
        u16::from_be_bytes(
            staker_runtime[staker_runtime.len() - 2..]
                .try_into()
                .expect("CBOR length suffix")
        ) as usize,
        metadata_len
    );
    let dependency = &manifest["wsteth_dependency"];
    for (path_key, hash_key) in [
        ("evidence_manifest", "evidence_manifest_sha256"),
        ("runtime_file", "runtime_file_sha256"),
        ("source_file", "source_file_sha256"),
        ("wrap_abi_file", "wrap_abi_file_sha256"),
    ] {
        let bytes = fs::read(root.join(required_str(dependency, path_key)))
            .unwrap_or_else(|error| panic!("read reused wstETH evidence: {error}"));
        assert_eq!(sha256_hex(&bytes), required_str(dependency, hash_key));
    }
    let wsteth_runtime = read_hex(&root.join(required_str(dependency, "runtime_file")));
    assert_eq!(
        wsteth_runtime.len() as u64,
        dependency["runtime_bytes"].as_u64().expect("wstETH bytes")
    );
    assert_eq!(
        keccak_hex(&wsteth_runtime),
        required_str(dependency, "runtime_keccak256")
    );
}

#[test]
fn lido_staking_archived_explorer_responses_bind_source_to_fixed_block_runtime() {
    let evidence = lido_staking_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let cases = [
        (
            "lido_implementation",
            "0x6ca84080381e43938476814be61b779a8bb6a600",
            "Lido",
            "v0.4.24+commit.e67f0147",
            "constantinople",
            "contracts/0.4.24/Lido.sol",
            "source/Lido.sol",
            "runtime/Lido.mainnet.hex",
            36usize,
            112usize,
            None,
        ),
        (
            "referral_staker",
            "0xa88f0329c2c4ce51ba3fc619bbf44efe7120dd0d",
            "WstETHReferralStaker",
            "0.8.25+commit.b61c2a91",
            "cancun",
            "si-contracts/0.8.25/w/WstethStaker.sol",
            "source/WstethStaker.sol",
            "runtime/WstETHReferralStaker.mainnet.hex",
            4usize,
            6usize,
            Some("0x0000000000000000000000007f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
        ),
    ];

    for (
        key,
        address,
        contract_name,
        compiler,
        evm_version,
        file_path,
        source_file,
        runtime_file,
        additional_source_count,
        abi_entry_count,
        constructor_args,
    ) in cases
    {
        let spec = &manifest["verified_explorer"][key];
        assert_eq!(required_str(spec, "address"), address);
        assert!(required_str(spec, "api").ends_with(address));
        assert_eq!(required_str(spec, "contract_name"), contract_name);
        assert_eq!(required_str(spec, "compiler"), compiler);
        assert_eq!(required_str(spec, "evm_version"), evm_version);
        assert_eq!(required_str(spec, "file_path"), file_path);
        assert_eq!(spec["fully_verified"].as_bool(), Some(true));
        assert_eq!(spec["source_matches_archive"].as_bool(), Some(true));
        assert_eq!(
            spec["deployed_bytecode_matches_fixed_block_runtime"].as_bool(),
            Some(true)
        );
        assert_eq!(
            spec["additional_sources"].as_u64(),
            Some(additional_source_count as u64)
        );
        assert_eq!(spec["abi_entries"].as_u64(), Some(abi_entry_count as u64));

        let response_bytes = fs::read(evidence.join(required_str(spec, "archive_file")))
            .unwrap_or_else(|error| panic!("read archived {key} explorer response: {error}"));
        assert_eq!(
            sha256_hex(&response_bytes),
            required_str(spec, "archive_file_sha256")
        );
        let response: Value = serde_json::from_slice(&response_bytes)
            .unwrap_or_else(|error| panic!("parse archived {key} explorer response: {error}"));

        assert_eq!(response["name"].as_str(), Some(contract_name));
        assert_eq!(response["compiler_version"].as_str(), Some(compiler));
        assert_eq!(response["evm_version"].as_str(), Some(evm_version));
        assert_eq!(response["file_path"].as_str(), Some(file_path));
        assert_eq!(response["language"].as_str(), Some("solidity"));
        assert_eq!(response["is_verified"].as_bool(), Some(true));
        assert_eq!(response["is_fully_verified"].as_bool(), Some(true));
        assert_eq!(response["is_partially_verified"].as_bool(), Some(false));
        assert_eq!(response["is_changed_bytecode"].as_bool(), Some(false));
        assert_eq!(response["creation_status"].as_str(), Some("success"));
        assert!(response["conflicting_implementations"].is_null());
        assert!(response["proxy_type"].is_null());
        assert_eq!(
            response["implementations"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(
            response["optimization_enabled"].as_bool(),
            spec["optimizer_enabled"].as_bool()
        );
        assert_eq!(
            response["optimization_runs"].as_u64(),
            spec["optimizer_runs"].as_u64()
        );
        assert_eq!(
            response["compiler_settings"]["evmVersion"].as_str(),
            Some(evm_version)
        );
        assert_eq!(
            response["compiler_settings"]["optimizer"]["enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["compiler_settings"]["optimizer"]["runs"].as_u64(),
            Some(200)
        );
        assert!(response["compiler_settings"]
            .as_object()
            .is_some_and(|v| !v.is_empty()));
        assert!(!required_str(&response, "creation_bytecode").is_empty());

        let official_source = fs::read(evidence.join(source_file))
            .unwrap_or_else(|error| panic!("read official {key} source: {error}"));
        assert_eq!(
            required_str(&response, "source_code").as_bytes(),
            official_source,
            "Blockscout's verified primary source must equal the official archive"
        );
        let fixed_block_runtime = read_hex(&evidence.join(runtime_file));
        assert_eq!(
            decode_hex_text(required_str(&response, "deployed_bytecode")),
            fixed_block_runtime,
            "Blockscout's verified deployed bytecode must equal both fixed-block RPC observations"
        );

        let additional_sources = response["additional_sources"]
            .as_array()
            .expect("complete explorer response retains additional sources");
        assert_eq!(additional_sources.len(), additional_source_count);
        let mut additional_paths = BTreeSet::new();
        for source in additional_sources {
            assert!(additional_paths.insert(required_str(source, "file_path")));
            assert!(!required_str(source, "source_code").is_empty());
        }
        let abi = response["abi"]
            .as_array()
            .expect("complete explorer response retains full ABI");
        assert_eq!(abi.len(), abi_entry_count);
        assert_eq!(response["constructor_args"].as_str(), constructor_args);
    }

    let staker_response = read_json(&evidence.join(required_str(
        &manifest["verified_explorer"]["referral_staker"],
        "archive_file",
    )));
    assert_eq!(
        staker_response["abi"],
        read_json(&evidence.join("abi/WstETHReferralStaker.abi.json"))
    );
    assert_eq!(
        decode_abi_word_address(required_str(&staker_response, "constructor_args")),
        required_str(
            &manifest["deployment"]["referral_staker"],
            "constructor_wsteth"
        )
    );

    let lido_response = read_json(&evidence.join(required_str(
        &manifest["verified_explorer"]["lido_implementation"],
        "archive_file",
    )));
    let archived_submit = read_json(&evidence.join("abi/Lido.submit.abi.json"));
    let verified_submit = lido_response["abi"]
        .as_array()
        .expect("Lido full verified ABI")
        .iter()
        .find(|entry| {
            entry["type"].as_str() == Some("function") && entry["name"].as_str() == Some("submit")
        })
        .expect("verified Lido ABI contains submit");
    assert_eq!(verified_submit, &archived_submit[0]);
}

#[test]
fn lido_staking_source_abi_descriptor_and_ir_bind_both_routes() {
    let root = workspace_root();
    let evidence = lido_staking_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    let lido_source_spec = &manifest["upstream"]["lido_core"]["source"];
    let lido_source_bytes = fs::read(evidence.join(required_str(lido_source_spec, "archive_file")))
        .expect("read official Lido source");
    assert_eq!(
        sha256_hex(&lido_source_bytes),
        required_str(lido_source_spec, "sha256")
    );
    let lido_source = String::from_utf8(lido_source_bytes).expect("Lido source is UTF-8");
    assert_eq!(
        normalized_solidity_function(&lido_source, "function submit(address _referral)"),
        "function submit(address _referral) external payable returns (uint256) { return _submit(_referral); }"
    );
    assert_eq!(
        normalized_solidity_function(&lido_source, "function _submit(address _referral)"),
        "function _submit(address _referral) internal returns (uint256) { require(msg.value != 0, \"ZERO_DEPOSIT\"); _decreaseStakingLimit(msg.value); uint256 sharesAmount = getSharesByPooledEth(msg.value); _mintShares(msg.sender, sharesAmount); _setBufferedEther(_getBufferedEther() + msg.value); emit Submitted(msg.sender, msg.value, _referral); _emitTransferAfterMintingShares(msg.sender, sharesAmount); return sharesAmount; }"
    );

    let staker_source_spec = &manifest["upstream"]["si_lidity"]["source"];
    let staker_source_bytes =
        fs::read(evidence.join(required_str(staker_source_spec, "archive_file")))
            .expect("read official referral-staker source");
    assert_eq!(
        sha256_hex(&staker_source_bytes),
        required_str(staker_source_spec, "sha256")
    );
    let staker_source =
        String::from_utf8(staker_source_bytes).expect("referral-staker source is UTF-8");
    assert_eq!(
        normalized_solidity_function(&staker_source, "constructor(IWstETH _wstETH)"),
        "constructor(IWstETH _wstETH) { wstETH = _wstETH; stETH = IStETH(wstETH.stETH()); stETH.approve(address(wstETH), type(uint256).max); }"
    );
    assert_eq!(
        normalized_solidity_function(&staker_source, "function stakeETH(address _referral)"),
        "function stakeETH(address _referral) external payable returns (uint256) { uint256 stethAmount = _getPooledEthBySharesRoundUp(stETH.submit{value: msg.value}(_referral)); uint256 wstETHAmount = wstETH.wrap(stethAmount); wstETH.transfer(msg.sender, wstETHAmount); return wstETHAmount; }"
    );
    assert_eq!(
        normalized_solidity_function(
            &staker_source,
            "function _getPooledEthBySharesRoundUp(uint256 _sharesAmount)"
        ),
        "function _getPooledEthBySharesRoundUp(uint256 _sharesAmount) internal view returns (uint256) { uint256 numeratorInEther = stETH.getTotalPooledEther(); uint256 denominatorInShares = stETH.getTotalShares(); return Math.ceilDiv(_sharesAmount * numeratorInEther, denominatorInShares); }"
    );
    assert_eq!(
        normalized_solidity_function(&staker_source, "receive() external payable"),
        "receive() external payable { revert EthTransferNotAllowed(); }"
    );
    assert!(staker_source.contains("can be zero address"));

    let submit_abi_spec = &manifest["abi"]["lido_submit"];
    let submit_abi_bytes = fs::read(evidence.join(required_str(submit_abi_spec, "archive_file")))
        .expect("read Lido submit ABI");
    assert_eq!(
        sha256_hex(&submit_abi_bytes),
        required_str(submit_abi_spec, "archive_file_sha256")
    );
    let submit_abi: Value = serde_json::from_slice(&submit_abi_bytes).expect("parse submit ABI");
    let submit = &submit_abi.as_array().expect("submit ABI array")[0];
    assert_eq!(submit["name"].as_str(), Some("submit"));
    assert_eq!(submit["stateMutability"].as_str(), Some("payable"));
    assert_eq!(submit["inputs"][0]["type"].as_str(), Some("address"));
    assert_eq!(submit["outputs"][0]["type"].as_str(), Some("uint256"));

    let staker_abi_spec = &manifest["abi"]["referral_staker"];
    let staker_abi_bytes = fs::read(evidence.join(required_str(staker_abi_spec, "archive_file")))
        .expect("read referral-staker ABI");
    assert_eq!(
        sha256_hex(&staker_abi_bytes),
        required_str(staker_abi_spec, "archive_file_sha256")
    );
    let staker_abi: Value =
        serde_json::from_slice(&staker_abi_bytes).expect("parse referral-staker ABI");
    assert_eq!(staker_abi.as_array().map(Vec::len), Some(6));
    let stake_eth = staker_abi
        .as_array()
        .expect("referral-staker ABI array")
        .iter()
        .find(|entry| {
            entry["type"].as_str() == Some("function") && entry["name"].as_str() == Some("stakeETH")
        })
        .expect("stakeETH ABI entry");
    assert_eq!(stake_eth["stateMutability"].as_str(), Some("payable"));
    assert_eq!(stake_eth["inputs"][0]["type"].as_str(), Some("address"));
    assert_eq!(stake_eth["outputs"][0]["type"].as_str(), Some("uint256"));
    for getter in ["stETH", "wstETH"] {
        let entry = staker_abi
            .as_array()
            .expect("referral-staker ABI array")
            .iter()
            .find(|entry| {
                entry["type"].as_str() == Some("function") && entry["name"].as_str() == Some(getter)
            })
            .unwrap_or_else(|| panic!("missing {getter} immutable getter"));
        assert_eq!(entry["stateMutability"].as_str(), Some("view"));
        assert_eq!(entry["outputs"][0]["type"].as_str(), Some("address"));
    }

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let registry_root = root.join("secure/data/erc7730-registry");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    for route in manifest["descriptors"]
        .as_array()
        .expect("Lido descriptor routes")
    {
        let descriptor_path = root.join(required_str(route, "file"));
        let descriptor = read_json(&descriptor_path);
        let deployment = &descriptor["context"]["contract"]["deployments"][0];
        assert_eq!(deployment["chainId"].as_u64(), Some(1));
        assert!(deployment["address"]
            .as_str()
            .expect("descriptor deployment address")
            .eq_ignore_ascii_case(required_str(route, "address")));
        let authored_signature = required_str(route, "authored_signature");
        let descriptor_format = &descriptor["display"]["formats"][authored_signature];
        assert_eq!(
            descriptor_format["intent"].as_str(),
            Some(required_str(route, "intent"))
        );
        assert_eq!(
            descriptor_format["interpolatedIntent"].as_str(),
            Some(required_str(route, "interpolated_intent"))
        );
        let descriptor_fields = descriptor_format["fields"]
            .as_array()
            .expect("Lido descriptor fields");
        assert_eq!(descriptor_fields.len(), 2);
        assert_eq!(
            descriptor_fields[0]["label"].as_str(),
            Some(required_str(route, "amount_label"))
        );
        assert_eq!(descriptor_fields[0]["path"].as_str(), Some("@.value"));
        assert_eq!(descriptor_fields[0]["format"].as_str(), Some("amount"));
        assert_eq!(descriptor_fields[1]["label"].as_str(), Some("Referral"));
        assert_eq!(descriptor_fields[1]["path"].as_str(), Some("#._referral"));
        assert_eq!(descriptor_fields[1]["format"].as_str(), Some("raw"));
        assert_eq!(descriptor_fields[1]["visible"].as_str(), Some("always"));

        let source_name = descriptor_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("descriptor file name");
        let contract: [u8; 20] = decode_hex_text(required_str(route, "address"))
            .try_into()
            .expect("Lido deployment address width");
        let entry = registry
            .entries
            .iter()
            .find(|entry| {
                entry.chain_id == 1
                    && entry.contract == contract
                    && entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .unwrap_or_else(|| panic!("missing generated Lido leaf for {source_name}"));
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse generated Lido IR");
        assert_eq!(cross_check_contract(&ir, 1, &contract), Ok(()));
        let canonical_signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = keccak256(canonical_signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert_eq!(
            format!("0x{}", hex::encode(selector)),
            required_str(route, "selector")
        );
        let format = ir
            .find_format_by_selector(&selector)
            .expect("Lido format table parses")
            .expect("Lido staking route remains admitted");
        assert_eq!(format.intent, b"Stake ETH");
        assert_eq!(format.static_head_words, 1);
        assert_eq!(format.nested_descent_count, 0);
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("generated Lido field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(
            fields[0].label,
            required_str(route, "amount_label").as_bytes()
        );
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::Amount)
        );
        let mut value_path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
        value_path.extend_from_slice(&container_field::VALUE.to_be_bytes());
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("Lido value path parses"),
            value_path
        );
        let amount_params = parse_params(&ir, fields[0].param_off).expect("Lido amount params");
        assert_eq!(amount_params.visibility, Visibility::Always);
        assert_eq!(amount_params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(amount_params.integer_width_bytes, Some(32));
        assert!(amount_params.token.is_none());
        assert!(amount_params.token_path.is_none());

        assert_eq!(fields[1].label, b"Referral");
        assert_eq!(FormatOp::try_from(fields[1].format_op), Ok(FormatOp::Raw));
        assert_eq!(
            ir.path_bytes(fields[1].path_off)
                .expect("Lido referral path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0,]
        );
        let referral_params = parse_params(&ir, fields[1].param_off).expect("Lido referral params");
        assert_eq!(referral_params.visibility, Visibility::Always);
        assert_eq!(referral_params.terminal_kind, Some(TerminalKind::Address));
        assert!(registry.known_calls.contains(&(1, contract, selector)));
    }

    let semantics = manifest["semantics"].as_array().expect("Lido semantics");
    assert_eq!(semantics.len(), 2);
    assert!(semantics
        .iter()
        .all(|route| required_str(route, "output_residual").contains("no signed minimum")));
    assert!(manifest["residuals"]
        .as_array()
        .expect("Lido residuals")
        .iter()
        .any(|residual| residual
            .as_str()
            .is_some_and(|text| text.contains("upgradeable Aragon proxy"))));
}

#[test]
fn lido_steth_erc20_source_abi_descriptor_metadata_and_ir_agree() {
    let root = workspace_root();
    let evidence = lido_staking_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let route_spec = &manifest["additional_routes"]["steth_erc20"];
    let routes = route_spec["routes"]
        .as_array()
        .expect("stETH ERC-20 route inventory");
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes
            .iter()
            .map(|route| required_str(route, "key"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["approve", "transfer"])
    );

    let explorer_spec = &manifest["verified_explorer"]["lido_implementation"];
    let explorer = read_json(&evidence.join(required_str(explorer_spec, "archive_file")));
    let additional_sources = explorer["additional_sources"]
        .as_array()
        .expect("verified Lido additional sources");
    let mut inherited = BTreeMap::<String, String>::new();
    for source_spec in manifest["upstream"]["lido_core"]["inherited_sources"]
        .as_array()
        .expect("inherited source inventory")
    {
        let path = required_str(source_spec, "explorer_additional_source_path");
        assert_eq!(required_str(source_spec, "upstream_path"), path);
        assert_eq!(required_str(source_spec, "git_blob").len(), 40);
        let matches: Vec<_> = additional_sources
            .iter()
            .filter(|source| source["file_path"].as_str() == Some(path))
            .collect();
        assert_eq!(matches.len(), 1, "verified source match for {path}");
        let source = required_str(matches[0], "source_code");
        assert_eq!(source.len() as u64, source_spec["bytes"].as_u64().unwrap());
        assert_eq!(
            sha256_hex(source.as_bytes()),
            required_str(source_spec, "sha256")
        );
        inherited.insert(path.to_owned(), source.to_owned());
    }
    assert_eq!(inherited.len(), 2);
    let steth_permit = &inherited["contracts/0.4.24/StETHPermit.sol"];
    let steth = &inherited["contracts/0.4.24/StETH.sol"];
    assert!(steth_permit.contains("import {StETH} from \"./StETH.sol\";"));
    assert!(steth_permit.contains("contract StETHPermit is IERC2612, StETH"));

    let lido_source = fs::read_to_string(evidence.join(required_str(
        &manifest["upstream"]["lido_core"]["source"],
        "archive_file",
    )))
    .expect("read official Lido source");
    assert!(lido_source.contains("import {StETHPermit} from \"./StETHPermit.sol\";"));
    assert!(lido_source.contains("contract Lido is Versioned, StETHPermit, AragonApp"));

    assert!(steth.contains("uint256 constant internal INFINITE_ALLOWANCE = ~uint256(0);"));
    assert_eq!(
        normalized_solidity_function(steth, "function approve(address _spender, uint256 _amount)"),
        "function approve(address _spender, uint256 _amount) external returns (bool) { _approve(msg.sender, _spender, _amount); return true; }"
    );
    assert_eq!(
        normalized_solidity_function(steth, "function transfer(address _recipient, uint256 _amount)"),
        "function transfer(address _recipient, uint256 _amount) external returns (bool) { _transfer(msg.sender, _recipient, _amount); return true; }"
    );
    assert_eq!(
        normalized_solidity_function(steth, "function _approve(address _owner, address _spender, uint256 _amount)"),
        "function _approve(address _owner, address _spender, uint256 _amount) internal { require(_owner != address(0), \"APPROVE_FROM_ZERO_ADDR\"); require(_spender != address(0), \"APPROVE_TO_ZERO_ADDR\"); allowances[_owner][_spender] = _amount; emit Approval(_owner, _spender, _amount); }"
    );
    assert_eq!(
        normalized_solidity_function(steth, "function _spendAllowance(address _owner, address _spender, uint256 _amount)"),
        "function _spendAllowance(address _owner, address _spender, uint256 _amount) internal { uint256 currentAllowance = allowances[_owner][_spender]; if (currentAllowance != INFINITE_ALLOWANCE) { require(currentAllowance >= _amount, \"ALLOWANCE_EXCEEDED\"); _approve(_owner, _spender, currentAllowance - _amount); } }"
    );
    assert_eq!(
        normalized_solidity_function(steth, "function getSharesByPooledEth(uint256 _ethAmount)"),
        "function getSharesByPooledEth(uint256 _ethAmount) public view returns (uint256) { require(_ethAmount < UINT128_MAX, \"ETH_TOO_LARGE\"); return (_ethAmount * _getShareRateDenominator()) / _getShareRateNumerator(); }"
    );
    assert_eq!(
        normalized_solidity_function(steth, "function _transfer(address _sender, address _recipient, uint256 _amount)"),
        "function _transfer(address _sender, address _recipient, uint256 _amount) internal { uint256 _sharesToTransfer = getSharesByPooledEth(_amount); _transferShares(_sender, _recipient, _sharesToTransfer); _emitTransferEvents(_sender, _recipient, _amount, _sharesToTransfer); }"
    );

    let descriptor_bytes = fs::read(root.join(required_str(route_spec, "descriptor_file")))
        .expect("read installed stETH descriptor");
    assert_eq!(
        descriptor_bytes,
        fs::read(root.join(required_str(route_spec, "curated_file")))
            .expect("read curated stETH descriptor"),
        "curated and installed stETH descriptors diverged"
    );
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse stETH descriptor");
    let deployment = &descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("stETH deployment array")[0];
    assert_eq!(
        deployment["chainId"].as_u64(),
        route_spec["chain_id"].as_u64()
    );
    assert!(deployment["address"]
        .as_str()
        .expect("stETH deployment address")
        .eq_ignore_ascii_case(required_str(route_spec, "address")));
    assert!(descriptor["metadata"]["constants"]["stETHaddress"]
        .as_str()
        .expect("stETH token constant")
        .eq_ignore_ascii_case(required_str(route_spec, "address")));

    let full_abi = explorer["abi"].as_array().expect("verified Lido ABI");
    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("stETH descriptor formats");
    for route in routes {
        let signature = required_str(route, "canonical_signature");
        let (name, params) = signature.split_once('(').expect("canonical signature");
        let input_types: Vec<_> = params
            .strip_suffix(')')
            .expect("canonical signature close")
            .split(',')
            .collect();
        let abi_matches: Vec<_> = full_abi
            .iter()
            .filter(|entry| {
                entry["type"].as_str() == Some("function")
                    && entry["name"].as_str() == Some(name)
                    && entry["inputs"].as_array().is_some_and(|inputs| {
                        inputs
                            .iter()
                            .filter_map(|input| input["type"].as_str())
                            .eq(input_types.iter().copied())
                    })
            })
            .collect();
        assert_eq!(abi_matches.len(), 1, "verified ABI route for {signature}");
        assert_eq!(
            abi_matches[0]["stateMutability"].as_str(),
            Some("nonpayable")
        );
        assert_eq!(abi_matches[0]["outputs"][0]["type"].as_str(), Some("bool"));

        let authored = required_str(route, "authored_signature");
        let format = &formats[authored];
        assert_eq!(
            format["intent"].as_str(),
            Some(required_str(route, "intent"))
        );
        let fields = format["fields"].as_array().expect("stETH route fields");
        assert_eq!(
            fields
                .iter()
                .map(|field| field["path"].as_str().expect("field path"))
                .collect::<Vec<_>>(),
            route["displayed_operand_paths"]
                .as_array()
                .expect("manifest displayed paths")
                .iter()
                .map(|path| path.as_str().expect("manifest displayed path"))
                .collect::<Vec<_>>()
        );
        assert!(fields.iter().all(|field| field["visible"] == "always"));
        if required_str(route, "key") == "approve" {
            assert_eq!(
                fields[1]["params"]["threshold"].as_str(),
                Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            );
            assert_eq!(fields[1]["params"]["message"].as_str(), Some("Unlimited"));
            assert!(required_str(route, "max_semantics").contains("uint256::MAX"));
            assert!(required_str(route, "max_semantics").contains("every smaller"));
        } else {
            assert!(fields[1]["params"]["threshold"].is_null());
            assert!(required_str(route, "state_residual").contains("floor rounding"));
            assert!(required_str(route, "state_residual").contains("zero shares"));
        }
    }

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let metadata: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(route_spec, "address"))
        })
        .collect();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].name, "Liquid staked Ether 2.0");
    assert_eq!(metadata[0].symbol, "stETH");
    assert_eq!(metadata[0].decimals, 18);

    let contract: [u8; 20] = decode_hex_text(required_str(route_spec, "address"))
        .try_into()
        .expect("stETH contract width");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let registry_root = root.join("secure/data/erc7730-registry");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == contract
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-stETH.json")
        })
        .expect("generated stETH leaf");
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse generated stETH IR");
    assert_eq!(cross_check_contract(&ir, 1, &contract), Ok(()));
    for route in routes {
        let signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("stETH selector width");
        assert_eq!(
            format!("0x{}", hex::encode(selector)),
            required_str(route, "selector")
        );
        assert!(registry.known_calls.contains(&(1, contract, selector)));
        let format = ir
            .find_format_by_selector(&selector)
            .expect("stETH format table parses")
            .expect("stETH ERC-20 route remains admitted");
        assert_eq!(format.static_head_words, 2);
        assert_eq!(format.nested_descent_count, 0);
        assert_eq!(format.intent, required_str(route, "intent").as_bytes());
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("generated stETH field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::AddressName)
        );
        assert_eq!(
            FormatOp::try_from(fields[1].format_op),
            Ok(FormatOp::TokenAmount)
        );
        let address_params = parse_params(&ir, fields[0].param_off).expect("address params");
        assert_eq!(address_params.visibility, Visibility::Always);
        assert_eq!(address_params.terminal_kind, Some(TerminalKind::Address));
        let amount_params = parse_params(&ir, fields[1].param_off).expect("amount params");
        assert_eq!(amount_params.visibility, Visibility::Always);
        assert_eq!(amount_params.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(amount_params.integer_width_bytes, Some(32));
        assert_eq!(amount_params.token.copied(), Some(contract));
        if required_str(route, "key") == "approve" {
            assert_eq!(amount_params.threshold.copied(), Some([0xff; 32]));
            assert_eq!(amount_params.message, Some(b"Unlimited".as_slice()));
        } else {
            assert!(amount_params.threshold.is_none());
            assert!(amount_params.message.is_none());
        }
    }
}

#[test]
fn stakewise_fixed_block_runtimes_match_the_archived_receipt() {
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
    );

    let artifacts = manifest["runtime_artifacts"]
        .as_object()
        .expect("runtime_artifacts object");
    let mut decoded = BTreeMap::<String, Vec<u8>>::new();
    for (name, spec) in artifacts {
        let bytes = read_hex(&evidence.join(required_str(spec, "file")));
        assert_eq!(
            bytes.len() as u64,
            spec["bytes"].as_u64().expect("runtime byte count"),
            "{name} byte count drifted"
        );
        assert_eq!(
            keccak_hex(&bytes),
            required_str(spec, "keccak256"),
            "{name} code hash drifted"
        );
        decoded.insert(name.clone(), bytes);
    }

    let slot = decode_hex_text(required_str(&manifest, "eip1967_implementation_slot"));
    let proxy = decoded.get("proxy").expect("proxy runtime");
    assert!(
        proxy.windows(slot.len()).any(|window| window == slot),
        "archived proxy runtime must embed the EIP-1967 implementation slot"
    );

    let implementation = decode_hex_text(required_str(&manifest, "implementation_address"));
    assert_eq!(implementation.len(), 20);
    let deployments = manifest["deployments"]
        .as_array()
        .expect("deployments array");
    assert_eq!(deployments.len(), 3);
    for deployment in deployments {
        let word = decode_hex_text(required_str(deployment, "implementation_slot_value"));
        assert_eq!(word.len(), 32);
        assert_eq!(&word[..12], &[0u8; 12]);
        assert_eq!(&word[12..], implementation.as_slice());
        assert!(decoded.contains_key(required_str(deployment, "implementation_runtime")));
    }

    let blocks = manifest["blocks"].as_array().expect("blocks array");
    assert_eq!(blocks.len(), 2);
    for block in blocks {
        assert_eq!(
            block["rpc_endpoints"]
                .as_array()
                .expect("RPC endpoint array")
                .len(),
            2,
            "each fixed block must have two independent observations"
        );
        assert_eq!(decode_hex_text(required_str(block, "hash")).len(), 32);
        assert_eq!(decode_hex_text(required_str(block, "state_root")).len(), 32);
    }

    let mut mainnet = decoded
        .get("implementation_mainnet")
        .expect("mainnet implementation")
        .clone();
    let mut hoodi = decoded
        .get("implementation_hoodi")
        .expect("Hoodi implementation")
        .clone();
    assert_eq!(mainnet.len(), hoodi.len());

    let ranges = manifest["cross_chain_runtime"]["variant_ranges"]
        .as_array()
        .expect("variant range array");
    assert_eq!(ranges.len(), 22, "variant-range inventory changed");
    let mut prior_end = 0usize;
    let mut label_counts = BTreeMap::<String, usize>::new();
    for range in ranges {
        let offset = range["offset"].as_u64().expect("range offset") as usize;
        let length = range["length"].as_u64().expect("range length") as usize;
        let end = offset.checked_add(length).expect("range end");
        assert!(
            offset >= prior_end,
            "variant ranges overlap or are unsorted"
        );
        assert!(end <= mainnet.len(), "variant range exceeds runtime");

        let expected_mainnet = decode_hex_text(required_str(range, "mainnet_hex"));
        let expected_hoodi = decode_hex_text(required_str(range, "hoodi_hex"));
        assert_eq!(expected_mainnet.len(), length);
        assert_eq!(expected_hoodi.len(), length);
        assert_eq!(&mainnet[offset..end], expected_mainnet.as_slice());
        assert_eq!(&hoodi[offset..end], expected_hoodi.as_slice());

        mainnet[offset..end].fill(0);
        hoodi[offset..end].fill(0);
        prior_end = end;
        *label_counts
            .entry(required_str(range, "label").to_owned())
            .or_default() += 1;
    }
    assert_eq!(
        label_counts,
        BTreeMap::from([
            ("chainId".to_owned(), 1),
            ("depositDataRegistry".to_owned(), 2),
            ("keeper".to_owned(), 5),
            ("osTokenConfig".to_owned(), 3),
            ("osTokenVaultController".to_owned(), 7),
            ("osTokenVaultEscrow".to_owned(), 1),
            ("sharedMevEscrow".to_owned(), 2),
            ("vaultsRegistry".to_owned(), 1),
        ])
    );
    assert_eq!(
        mainnet, hoodi,
        "implementation instruction bytes differ outside declared chain/address immutables"
    );
}

#[test]
fn stakewise_claim_source_abi_and_descriptors_agree_on_caller_semantics() {
    let root = workspace_root();
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    let verified_source = &manifest["verified_source"];
    assert_eq!(verified_source["upstream_release"].as_str(), Some("v4.0.1"));
    assert_eq!(
        verified_source["upstream_commit"].as_str(),
        Some("c511cd912cb881f60cf2a32d6c5d5f533e5d04b5")
    );
    assert_eq!(
        verified_source["upstream_tree"].as_str(),
        Some("6185defc0ea2c9d5e72f02bd3e1411e13684b7fc")
    );
    assert_eq!(
        verified_source["openzeppelin_submodule_commit"].as_str(),
        Some("60b305a8f3ff0c7688f02ac470417b6bbf1c4d27")
    );
    assert_eq!(
        verified_source["archived_files_match_verified_explorer_sources"].as_bool(),
        Some(true)
    );

    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in verified_source["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(sha256_hex(&bytes), required_str(source, "sha256"));
        archived_sources.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("Solidity source is UTF-8"),
        );
    }
    let eth_vault = &archived_sources["source/EthVault.sol"];
    assert!(eth_vault.contains("VaultEnterExit"));
    assert!(
        !eth_vault.contains("function claimExitedAssets"),
        "the concrete EthVault must inherit, not override, the audited claim semantics"
    );

    let module = &archived_sources["source/VaultEnterExit.sol"];
    let semantics = manifest["claim_semantics"]
        .as_object()
        .expect("claim semantics object");
    for key in [
        "request_lookup",
        "request_delete",
        "residual_request_key",
        "transfer_recipient",
        "event_recipient",
    ] {
        assert!(
            module.contains(required_str(&Value::Object(semantics.clone()), key)),
            "archived implementation lost the {key} msg.sender binding"
        );
    }

    let interface: String = archived_sources["source/IVaultEnterExit.sol"]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(interface.contains(
        "function claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex) external;"
    ));

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse route ABI");
    let entries = abi.as_array().expect("ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let input_types: Vec<_> = entry["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(input_types, ["uint256", "uint256", "uint256"]);
    let signature = format!(
        "{}({})",
        entry["name"].as_str().expect("ABI function name"),
        input_types.join(",")
    );
    assert_eq!(signature, required_str(&manifest, "canonical_signature"));

    let mut expected_by_descriptor = BTreeMap::<String, BTreeSet<(u64, String)>>::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("deployment array")
    {
        expected_by_descriptor
            .entry(required_str(deployment, "descriptor").to_owned())
            .or_default()
            .insert((
                deployment["chain_id"].as_u64().expect("deployment chain"),
                required_str(deployment, "address").to_ascii_lowercase(),
            ));
    }
    assert_eq!(expected_by_descriptor.len(), 2);

    for (descriptor_path, expected_deployments) in expected_by_descriptor {
        let descriptor_bytes =
            fs::read(root.join(&descriptor_path)).expect("read curated descriptor");
        let registry_suffix = descriptor_path
            .strip_prefix("secure/data/erc7730/curations/files/")
            .expect("curation descriptor prefix");
        assert_eq!(
            descriptor_bytes,
            fs::read(
                root.join("secure/data/erc7730-registry")
                    .join(registry_suffix)
            )
            .expect("read vendored descriptor"),
            "curation and production descriptor copies diverged"
        );
        let descriptor: Value = serde_json::from_slice(&descriptor_bytes).expect("descriptor JSON");
        let actual_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("descriptor deployments")
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().expect("descriptor chain"),
                    deployment["address"]
                        .as_str()
                        .expect("descriptor address")
                        .to_ascii_lowercase(),
                )
            })
            .collect();
        assert_eq!(actual_deployments, expected_deployments);

        let format = &descriptor["display"]["formats"]
            ["claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex)"];
        let fields = format["fields"].as_array().expect("claim display fields");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["label"].as_str(), Some("Claim receiver"));
        assert_eq!(fields[0]["path"].as_str(), Some("@.from"));
        assert_eq!(fields[0]["format"].as_str(), Some("addressName"));
        assert_eq!(fields[0]["visible"].as_str(), Some("always"));
        assert_eq!(fields[1]["path"].as_str(), Some("#.positionTicket"));
        assert_eq!(fields[2]["path"].as_str(), Some("#.timestamp"));
        assert_eq!(fields[3]["path"].as_str(), Some("#.exitQueueIndex"));
        assert!(fields.iter().all(|field| field["visible"] == "always"));
    }
}

#[test]
fn stakewise_deposit_and_exit_source_abi_descriptors_and_ir_agree() {
    let root = workspace_root();
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let additional = &manifest["additional_routes"];
    let routes = additional["routes"]
        .as_array()
        .expect("StakeWise additional routes array");
    let expected_routes = BTreeMap::from([
        ("deposit", ("deposit(address,address)", "0xf9609f08")),
        (
            "enterExitQueue",
            ("enterExitQueue(uint256,address)", "0x8ceab9aa"),
        ),
    ]);
    assert_eq!(
        routes
            .iter()
            .map(|route| required_str(route, "key"))
            .collect::<BTreeSet<_>>(),
        expected_routes.keys().copied().collect(),
        "StakeWise route inventory drifted"
    );

    let verified_source = &manifest["verified_source"];
    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in verified_source["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(source, "sha256"),
            "archived source hash drifted for {archive_file}"
        );
        archived_sources.insert(
            archive_file.to_owned(),
            normalized_whitespace(&String::from_utf8(bytes).expect("Solidity source is UTF-8")),
        );
    }

    let staking = &archived_sources["source/VaultEthStaking.sol"];
    assert!(staking.contains(
        "function deposit(address receiver, address referrer) public payable virtual override returns (uint256 shares) { return _deposit(receiver, msg.value, referrer); }"
    ));
    assert!(staking.contains(
        "function _vaultAssets() internal view virtual override returns (uint256) { return address(this).balance; }"
    ));
    assert!(staking.contains(
        "function _transferVaultAssets(address receiver, uint256 assets) internal virtual override nonReentrant { return Address.sendValue(payable(receiver), assets); }"
    ));

    let interface = &archived_sources["source/IVaultEthStaking.sol"];
    assert!(interface.contains(
        "function deposit(address receiver, address referrer) external payable returns (uint256 shares);"
    ));

    let enter_exit = &archived_sources["source/VaultEnterExit.sol"];
    assert_fragments_in_order(
        enter_exit,
        &[
            "function _deposit(address to, uint256 assets, address referrer)",
            "if (to == address(0)) revert Errors.ZeroAddress();",
            "if (assets == 0) revert Errors.InvalidAssets();",
            "if (totalAssetsAfter > capacity()) revert Errors.CapacityExceeded();",
            "shares = _convertToShares(assets, Math.Rounding.Ceil);",
            "_mintShares(to, shares);",
            "emit Deposited(msg.sender, to, assets, shares, referrer);",
        ],
    );
    assert_fragments_in_order(
        enter_exit,
        &[
            "function _enterExitQueue(address user, uint256 shares, address receiver)",
            "if (shares == 0) revert Errors.InvalidShares();",
            "if (receiver == address(0)) revert Errors.ZeroAddress();",
            "if (!_isCollateralized())",
            "uint256 assets = convertToAssets(shares);",
            "_burnShares(user, shares);",
            "_transferVaultAssets(receiver, assets);",
            "return type(uint256).max;",
            "positionTicket = _exitQueue.getLatestTotalTickets() + _totalExitingTickets + queuedShares;",
            "_exitRequests[keccak256(abi.encode(receiver, block.timestamp, positionTicket))] = shares;",
            "_balances[user] -= shares;",
            "_queuedShares = SafeCast.toUint128(queuedShares + shares);",
            "emit ExitQueueEntered(user, receiver, positionTicket, shares);",
        ],
    );

    let eth_vault = &archived_sources["source/EthVault.sol"];
    assert!(eth_vault.contains(
        "function enterExitQueue(uint256 shares, address receiver) public virtual override(IVaultEnterExit, VaultEnterExit, VaultOsToken) returns (uint256 positionTicket) { return super.enterExitQueue(shares, receiver); }"
    ));
    let os_token = &archived_sources["source/VaultOsToken.sol"];
    assert_fragments_in_order(
        os_token,
        &[
            "function enterExitQueue(uint256 shares, address receiver)",
            "positionTicket = super.enterExitQueue(shares, receiver);",
            "_checkOsTokenPosition(msg.sender);",
            "function _checkOsTokenPosition(address user) internal view",
            "if (position.shares == 0) return;",
            "_checkHarvested();",
            "if (_calcMaxOsTokenShares(convertToAssets(_balances[user])) < position.shares)",
            "revert Errors.LowLtv();",
        ],
    );
    let state = &archived_sources["source/VaultState.sol"];
    assert!(state.contains("mapping(address => uint256) internal _balances;"));
    assert!(state.contains(
        "function getShares(address account) external view override returns (uint256) { return _balances[account]; }"
    ));
    assert!(state.contains(
        "function convertToAssets(uint256 shares) public view override returns (uint256 assets)"
    ));
    assert!(state.contains(
        "function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares)"
    ));
    let immutables = &archived_sources["source/VaultImmutables.sol"];
    assert!(immutables.contains(
        "function _isCollateralized() internal view virtual returns (bool) { return IKeeperRewards(_keeper).isCollateralized(address(this)); }"
    ));

    let abi_spec = &additional["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read StakeWise additional-route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    assert_eq!(
        required_str(abi_spec, "source_full_verified_abi_canonical_sha256"),
        required_str(&manifest["abi"], "full_verified_abi_canonical_sha256"),
        "additional-route ABI subset lost its pinned full-ABI receipt"
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse additional-route ABI");
    let abi_entries = abi.as_array().expect("additional-route ABI array");
    assert_eq!(abi_entries.len(), routes.len());

    let mut expected_by_descriptor = BTreeMap::<String, BTreeSet<(u64, String)>>::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("deployment array")
    {
        expected_by_descriptor
            .entry(required_str(deployment, "descriptor").to_owned())
            .or_default()
            .insert((
                deployment["chain_id"].as_u64().expect("deployment chain"),
                required_str(deployment, "address").to_ascii_lowercase(),
            ));
    }

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &root.join("secure/data/erc7730-registry/registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&root.join("secure/data/erc7730-registry")),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    for runtime_key in ["implementation_mainnet", "implementation_hoodi"] {
        let runtime_spec = &manifest["runtime_artifacts"][runtime_key];
        let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
        for route in routes {
            let selector = decode_hex_text(required_str(route, "selector"));
            let mut push4 = vec![0x63];
            push4.extend_from_slice(&selector);
            assert_eq!(
                runtime
                    .windows(push4.len())
                    .filter(|window| *window == push4.as_slice())
                    .count(),
                1,
                "{runtime_key} must retain exactly one PUSH4 dispatcher entry for {}",
                required_str(route, "canonical_signature")
            );
        }
    }

    let canonicalize = |authored: &str| {
        let (name, tail) = authored.split_once('(').expect("authored signature");
        let params = tail.strip_suffix(')').expect("signature close");
        let types: Vec<_> = params
            .split(',')
            .filter(|param| !param.trim().is_empty())
            .map(|param| {
                param
                    .split_ascii_whitespace()
                    .next()
                    .expect("authored input type")
            })
            .collect();
        format!("{name}({})", types.join(","))
    };

    for (descriptor_path, expected_deployments) in expected_by_descriptor {
        let descriptor_bytes =
            fs::read(root.join(&descriptor_path)).expect("read curated StakeWise descriptor");
        let registry_suffix = descriptor_path
            .strip_prefix("secure/data/erc7730/curations/files/")
            .expect("curation descriptor prefix");
        assert_eq!(
            descriptor_bytes,
            fs::read(
                root.join("secure/data/erc7730-registry")
                    .join(registry_suffix)
            )
            .expect("read vendored StakeWise descriptor"),
            "curation and production descriptor copies diverged"
        );
        let descriptor: Value =
            serde_json::from_slice(&descriptor_bytes).expect("StakeWise descriptor JSON");
        let actual_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("descriptor deployments")
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().expect("descriptor chain"),
                    deployment["address"]
                        .as_str()
                        .expect("descriptor address")
                        .to_ascii_lowercase(),
                )
            })
            .collect();
        assert_eq!(actual_deployments, expected_deployments);
        let formats = descriptor["display"]["formats"]
            .as_object()
            .expect("descriptor formats");

        let source_name = Path::new(registry_suffix)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("descriptor file name");
        let matching_entries: Vec<_> = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect();
        assert_eq!(matching_entries.len(), expected_deployments.len());

        for route in routes {
            let key = required_str(route, "key");
            let signature = required_str(route, "canonical_signature");
            let (_, expected_selector) = expected_routes
                .get(key)
                .unwrap_or_else(|| panic!("unexpected StakeWise route {key}"));
            assert_eq!(required_str(route, "selector"), *expected_selector);
            assert_eq!(
                format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])),
                *expected_selector
            );

            let abi_matches: Vec<_> = abi_entries
                .iter()
                .filter(|entry| {
                    let Some(name) = entry["name"].as_str() else {
                        return false;
                    };
                    let Some(inputs) = entry["inputs"].as_array() else {
                        return false;
                    };
                    let types: Vec<_> = inputs
                        .iter()
                        .filter_map(|input| input["type"].as_str())
                        .collect();
                    format!("{name}({})", types.join(",")) == signature
                })
                .collect();
            assert_eq!(abi_matches.len(), 1, "exact additional-route ABI match");
            let abi_entry = abi_matches[0];
            assert_eq!(abi_entry["type"].as_str(), Some("function"));
            assert_eq!(
                abi_entry["stateMutability"].as_str(),
                Some(if key == "deposit" {
                    "payable"
                } else {
                    "nonpayable"
                })
            );
            assert_eq!(abi_entry["outputs"][0]["type"].as_str(), Some("uint256"));

            let descriptor_matches: Vec<_> = formats
                .iter()
                .filter(|(authored, _)| canonicalize(authored) == signature)
                .collect();
            assert_eq!(descriptor_matches.len(), 1, "exact descriptor route match");
            let (_, descriptor_format) = descriptor_matches[0];
            let descriptor_fields = descriptor_format["fields"]
                .as_array()
                .expect("descriptor fields");
            let displayed_paths: BTreeSet<_> = route["displayed_operand_paths"]
                .as_array()
                .expect("displayed operand paths")
                .iter()
                .map(|path| path.as_str().expect("displayed operand path"))
                .collect();
            assert_eq!(
                descriptor_fields
                    .iter()
                    .map(|field| field["path"].as_str().expect("descriptor field path"))
                    .collect::<BTreeSet<_>>(),
                displayed_paths,
                "{key} displayed operand inventory drifted"
            );
            if key == "deposit" {
                assert_eq!(
                    descriptor_fields[0]["label"].as_str(),
                    Some("Shares receiver"),
                    "StakeWise deposit must name the address that receives the minted shares"
                );
            } else if key == "enterExitQueue" {
                assert_eq!(descriptor_format["intent"].as_str(), Some("Exit vault"));
                assert_eq!(descriptor_fields.len(), 2);
                assert_eq!(
                    descriptor_fields[0]["label"].as_str(),
                    Some("Shares to exit")
                );
                assert_eq!(descriptor_fields[0]["format"].as_str(), Some("raw"));
                assert!(descriptor_fields[0]["params"].is_null());
                assert_eq!(
                    descriptor_fields[1]["label"].as_str(),
                    Some("Exit receiver")
                );
                assert_eq!(descriptor_fields[1]["format"].as_str(), Some("addressName"));
            }

            let selector: [u8; 4] = decode_hex_text(*expected_selector)
                .try_into()
                .expect("selector width");
            for entry in &matching_entries {
                let deployment = (entry.chain_id, format!("0x{}", hex::encode(entry.contract)));
                assert!(expected_deployments.contains(&deployment));
                let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated StakeWise IR parses");
                assert_eq!(
                    cross_check_contract(&ir, entry.chain_id, &entry.contract),
                    Ok(())
                );
                let ir_format = ir
                    .find_format_by_selector(&selector)
                    .expect("StakeWise format table parses")
                    .unwrap_or_else(|| panic!("{signature} remains admitted"));
                let ir_fields: Vec<_> = ir_format
                    .fields()
                    .map(|field| field.expect("generated StakeWise field parses"))
                    .collect();
                assert_eq!(ir_fields.len(), descriptor_fields.len());
                for (descriptor_field, ir_field) in descriptor_fields.iter().zip(ir_fields) {
                    let op = match descriptor_field["format"].as_str() {
                        Some("addressName") => FormatOp::AddressName,
                        Some("amount") => FormatOp::Amount,
                        Some("raw") => FormatOp::Raw,
                        other => panic!("unexpected StakeWise field formatter {other:?}"),
                    };
                    assert_eq!(
                        ir_field.label,
                        descriptor_field["label"].as_str().unwrap().as_bytes()
                    );
                    assert_eq!(FormatOp::try_from(ir_field.format_op), Ok(op));
                    let params = parse_params(&ir, ir_field.param_off).expect("field params parse");
                    assert_eq!(params.visibility, Visibility::Always);
                    let path = descriptor_field["path"]
                        .as_str()
                        .expect("descriptor field path");
                    assert_eq!(
                        params.terminal_kind,
                        Some(
                            if path.ends_with("receiver") || path.ends_with("referrer") {
                                TerminalKind::Address
                            } else {
                                TerminalKind::Unsigned
                            }
                        )
                    );
                    if key == "enterExitQueue" && path == "#.shares" {
                        assert!(params.token.is_none());
                        assert!(params.token_path.is_none());
                    }
                }
            }

            let effect = required_str(route, "successful_effect").to_ascii_lowercase();
            let residual = required_str(route, "state_residual").to_ascii_lowercase();
            if key == "deposit" {
                for needle in ["signed transaction value", "receiver", "referrer"] {
                    assert!(effect.contains(needle));
                }
                for needle in ["live", "share", "neither signed calldata nor displayed"] {
                    assert!(residual.contains(needle));
                }
            } else {
                for needle in ["msg.sender", "shares", "receiver", "collateralized"] {
                    assert!(effect.contains(needle));
                }
                for needle in ["collateralization", "ticket", "exchange rate", "live state"] {
                    assert!(residual.contains(needle));
                }
            }
        }
    }
}

#[test]
fn lido_wsteth_fixed_block_runtime_and_state_match_receipt() {
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    let selector = &keccak256(signature.as_bytes())[..4];
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(selector))
    );
    assert_eq!(selector, [0xd5, 0x05, 0xac, 0xcf]);

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(1));
    let contract_bytes = decode_hex_text(required_str(deployment, "address"));
    let contract: [u8; 20] = contract_bytes.try_into().expect("wstETH address width");
    assert_eq!(
        hex::encode(contract),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"
    );
    assert_eq!(deployment["block_number"].as_u64(), Some(11_888_477));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(4));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(
        required_str(deployment, "receipt_contract_address"),
        required_str(deployment, "address")
    );
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(7_277));
    assert_eq!(
        decode_hex_text(required_str(deployment, "transaction_hash")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(deployment, "creation_input_keccak256")).len(),
        32
    );
    assert_eq!(
        required_str(deployment, "constructor_argument_steth"),
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
    );

    for receipt in [deployment, &manifest["evidence_block"]] {
        let endpoints: BTreeSet<_> = receipt["rpc_endpoints"]
            .as_array()
            .expect("RPC endpoint array")
            .iter()
            .map(|endpoint| endpoint.as_str().expect("RPC endpoint string"))
            .collect();
        assert_eq!(
            endpoints.len(),
            2,
            "each receipt needs two independent RPC observations"
        );
        let hash_key = if receipt.get("block_hash").is_some() {
            "block_hash"
        } else {
            "hash"
        };
        assert_eq!(decode_hex_text(required_str(receipt, hash_key)).len(), 32);
    }
    let fixed_block = &manifest["evidence_block"];
    assert_eq!(fixed_block["number"].as_u64(), Some(25_566_776));
    assert_eq!(decode_hex_text(required_str(fixed_block, "hash")).len(), 32);
    assert_eq!(
        decode_hex_text(required_str(fixed_block, "state_root")).len(),
        32
    );

    let runtime_spec = &manifest["runtime"];
    let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().expect("runtime byte count")
    );
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    assert!(
        runtime
            .windows(selector.len())
            .any(|window| window == selector),
        "archived runtime lost the permit selector"
    );
    assert_eq!(
        runtime_spec["explorer_deployed_bytecode_matches_artifact"].as_bool(),
        Some(true)
    );
    assert_eq!(
        decode_hex_text(required_str(runtime_spec, "eip1967_implementation_slot")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(
            runtime_spec,
            "eip1967_implementation_slot_value"
        )),
        [0u8; 32],
        "fixed-block wstETH unexpectedly became an ERC-1967 proxy"
    );

    let calls = &manifest["fixed_block_calls"];
    for (name, canonical_signature) in [
        ("name", "name()"),
        ("symbol", "symbol()"),
        ("decimals", "decimals()"),
        ("steth", "stETH()"),
        ("domain_separator", "DOMAIN_SEPARATOR()"),
    ] {
        assert_eq!(
            required_str(&calls[name], "selector"),
            format!(
                "0x{}",
                hex::encode(&keccak256(canonical_signature.as_bytes())[..4])
            ),
            "{name} selector drifted"
        );
    }
    let token_name = decode_abi_string_result(required_str(&calls["name"], "result"));
    let token_symbol = decode_abi_string_result(required_str(&calls["symbol"], "result"));
    assert_eq!(token_name, required_str(&calls["name"], "decoded"));
    assert_eq!(token_symbol, required_str(&calls["symbol"], "decoded"));
    assert_eq!(token_name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(token_symbol, "wstETH");

    let decimals = decode_hex_text(required_str(&calls["decimals"], "result"));
    assert_eq!(decimals.len(), 32);
    assert_eq!(&decimals[..31], &[0u8; 31]);
    assert_eq!(
        decimals[31] as u64,
        calls["decimals"]["decoded"]
            .as_u64()
            .expect("decoded decimals")
    );
    assert_eq!(decimals[31], 18);

    let steth_word = decode_hex_text(required_str(&calls["steth"], "result"));
    assert_eq!(steth_word.len(), 32);
    assert_eq!(&steth_word[..12], &[0u8; 12]);
    assert_eq!(
        &steth_word[12..],
        decode_hex_text(required_str(&calls["steth"], "decoded")).as_slice()
    );
    assert_eq!(
        required_str(&calls["steth"], "decoded"),
        required_str(deployment, "constructor_argument_steth")
    );

    let domain = decode_hex_text(required_str(&calls["domain_separator"], "result"));
    assert_eq!(
        domain,
        eip712_domain_separator(&token_name, "1", 1, &contract),
        "fixed-block domain separator does not bind the archived name, version, chain, and contract"
    );
}

#[test]
fn lido_wsteth_source_abi_descriptor_and_metadata_agree_on_permit_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let source_spec = &manifest["verified_source"];

    assert_eq!(
        source_spec["compiler"].as_str(),
        Some("0.6.12+commit.27d51765")
    );
    assert_eq!(source_spec["evm_version"].as_str(), Some("istanbul"));
    assert_eq!(source_spec["optimizer_enabled"].as_bool(), Some(true));
    assert_eq!(source_spec["optimizer_runs"].as_u64(), Some(200));
    assert_eq!(
        source_spec["upstream_commit"].as_str(),
        Some("2b46615a11dee77d4d22066f942f6c6afab9b87a")
    );
    assert_eq!(
        source_spec["upstream_tree"].as_str(),
        Some("b4e0ba7c36530d279ff0c4f18b1ae6e68a272da7")
    );
    assert_eq!(source_spec["openzeppelin_version"].as_str(), Some("3.4.0"));
    assert_eq!(
        source_spec["openzeppelin_tag_commit"].as_str(),
        Some("fa64a1ced0b70ab89073d5d0b6e01b0778f7e7d6")
    );
    assert_eq!(
        source_spec["archived_upstream_lines_present_in_verified_flattened_source"].as_bool(),
        Some(true)
    );

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );
    let openzeppelin_bytes =
        fs::read(evidence.join(required_str(source_spec, "openzeppelin_file")))
            .expect("read archived OpenZeppelin source");
    assert_eq!(
        sha256_hex(&openzeppelin_bytes),
        required_str(source_spec, "openzeppelin_file_sha256")
    );

    let flattened = String::from_utf8(flattened_bytes).expect("flattened source is UTF-8");
    let flattened_lines: BTreeSet<_> = flattened.lines().map(str::trim).collect();
    for (label, source_bytes) in [
        ("official Lido WstETH", upstream_bytes),
        ("OpenZeppelin ERC20Permit", openzeppelin_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("archived source is UTF-8");
        for line in source.lines().map(str::trim).filter(|line| {
            !line.is_empty() && !line.starts_with("// SPDX") && !line.starts_with("import ")
        }) {
            assert!(
                flattened_lines.contains(line),
                "{label} line is absent from the verified flattened source: {line}"
            );
        }
    }

    let permit_signature =
        "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {";
    let permit_start = flattened
        .find(permit_signature)
        .expect("deployed permit implementation");
    let permit_tail = &flattened[permit_start..];
    let permit_end = permit_tail
        .find("function nonces(address owner)")
        .expect("permit implementation end");
    let permit = normalized_whitespace(&permit_tail[..permit_end]);
    assert_fragments_in_order(
        &permit,
        &[
            r#"require(block.timestamp <= deadline, "ERC20Permit: expired deadline");"#,
            "_PERMIT_TYPEHASH, owner, spender, value, _nonces[owner].current(), deadline",
            "bytes32 hash = _hashTypedDataV4(structHash);",
            "address signer = ECDSA.recover(hash, v, r, s);",
            r#"require(signer == owner, "ERC20Permit: invalid signature");"#,
            "_nonces[owner].increment();",
            "_approve(owner, spender, value);",
        ],
    );
    let flattened_normalized = normalized_whitespace(&flattened);
    assert!(flattened_normalized
        .contains(r#"constructor(string memory name) internal EIP712(name, "1") { }"#));
    assert_fragments_in_order(
        &flattened_normalized,
        &[
            "contract WstETH is ERC20Permit",
            r#"constructor(IStETH _stETH) public ERC20Permit("Wrapped liquid staked Ether 2.0") ERC20("Wrapped liquid staked Ether 2.0", "wstETH")"#,
            "stETH = _stETH;",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read permit ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse permit ABI");
    let entries = abi.as_array().expect("permit ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("permit"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let inputs = entry["inputs"].as_array().expect("permit ABI inputs");
    let input_names: Vec<_> = inputs
        .iter()
        .map(|input| input["name"].as_str().expect("ABI input name"))
        .collect();
    let input_types: Vec<_> = inputs
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(
        input_names,
        ["owner", "spender", "value", "deadline", "v", "r", "s"]
    );
    assert_eq!(
        input_types,
        ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"]
    );
    let abi_signature = format!("permit({})", input_types.join(","));
    assert_eq!(
        abi_signature,
        required_str(&manifest, "canonical_signature")
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor deployment address")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["wstETHaddress"]
            .as_str()
            .expect("wstETH token constant")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );

    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");
    let permits: Vec<_> = formats
        .iter()
        .filter(|(signature, _)| signature.starts_with("permit("))
        .collect();
    assert_eq!(permits.len(), 1);
    let fields = permits[0].1["fields"]
        .as_array()
        .expect("permit display fields");
    let expected_fields = [
        ("Owner", "#.owner", "addressName"),
        ("Spender", "#.spender", "addressName"),
        ("Amount", "#.value", "tokenAmount"),
        ("Deadline", "#.deadline", "date"),
        ("V", "#.v", "raw"),
        ("R", "#.r", "raw"),
        ("S", "#.s", "raw"),
    ];
    assert_eq!(fields.len(), expected_fields.len());
    for (field, (label, path, format)) in fields.iter().zip(expected_fields) {
        assert_eq!(field["label"].as_str(), Some(label));
        assert_eq!(field["path"].as_str(), Some(path));
        assert_eq!(field["format"].as_str(), Some(format));
        assert_eq!(field["visible"].as_str(), Some("always"));
    }
    let max_value_display = &descriptor_spec["max_value_display"];
    assert_eq!(
        fields[2]["params"]["threshold"].as_str(),
        Some(required_str(max_value_display, "threshold"))
    );
    assert_eq!(
        fields[2]["params"]["message"].as_str(),
        Some(required_str(max_value_display, "message"))
    );
    assert_eq!(required_str(max_value_display, "message"), "Max uint256");
    let max_meaning = required_str(max_value_display, "meaning");
    assert!(max_meaning.contains("one-to-one"));
    assert!(max_meaning.contains("does not claim"));
    assert!(max_meaning.contains("non-decrementing"));
    let manifest_paths: Vec<_> = descriptor_spec["permit_operand_paths"]
        .as_array()
        .expect("manifest operand paths")
        .iter()
        .map(|path| path.as_str().expect("manifest operand path"))
        .collect();
    let descriptor_paths: Vec<_> = fields
        .iter()
        .map(|field| field["path"].as_str().expect("descriptor field path"))
        .collect();
    assert_eq!(descriptor_paths, manifest_paths);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let metadata: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(&manifest["deployment"], "address"))
        })
        .collect();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(metadata[0].symbol, "wstETH");
    assert_eq!(metadata[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(
        (registry_entry.chain_id, registry_entry.contract),
        (1, {
            let mut address = [0u8; 20];
            address.copy_from_slice(&decode_hex_text(required_str(
                &manifest["deployment"],
                "address",
            )));
            address
        })
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    assert_eq!(
        cross_check_contract(&ir, 1, &registry_entry.contract),
        Ok(())
    );
    assert_eq!(
        cross_check_contract(&ir, 10, &registry_entry.contract),
        Err(BindingError::ChainIdMismatch)
    );
    let mut wrong_contract = registry_entry.contract;
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_contract(&ir, 1, &wrong_contract),
        Err(BindingError::ContractMismatch)
    );
    let permit_selector: [u8; 4] =
        keccak256(required_str(&manifest, "canonical_signature").as_bytes())[..4]
            .try_into()
            .expect("permit selector width");
    let format = ir
        .find_format_by_selector(&permit_selector)
        .expect("Lido format table parses")
        .expect("Lido permit remains admitted");
    let ir_fields: Vec<_> = format
        .fields()
        .map(|field| field.expect("generated permit field parses"))
        .collect();
    assert_eq!(ir_fields.len(), 7);
    let amount_params = parse_params(&ir, ir_fields[2].param_off).expect("permit amount params");
    assert_eq!(amount_params.threshold.copied(), Some([0xff; 32]));
    assert_eq!(amount_params.message, Some(b"Max uint256".as_slice()));

    assert!(manifest["residuals"]
        .as_array()
        .expect("residual array")
        .iter()
        .any(|residual| residual
            .as_str()
            .is_some_and(|text| text.contains("nonce") && text.contains("not signed calldata"))));
}

#[test]
fn lido_wsteth_wrap_source_abi_descriptor_and_metadata_agree_on_input_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let deployment = &manifest["deployment"];
    let source_spec = &manifest["verified_source"];
    let wrap_spec = &manifest["additional_routes"]["wrap"];
    let signature = required_str(wrap_spec, "canonical_signature");

    assert_eq!(signature, "wrap(uint256)");
    let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("wrap selector width");
    assert_eq!(selector, [0xea, 0x59, 0x8c, 0xb0]);
    assert_eq!(required_str(wrap_spec, "selector"), "0xea598cb0");

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived official Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );

    for (label, source_bytes) in [
        ("verified flattened", flattened_bytes),
        ("official Lido", upstream_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("wrap source is UTF-8");
        let wrap_start = source
            .find("function wrap(uint256 _stETHAmount) external returns (uint256) {")
            .unwrap_or_else(|| panic!("{label} wrap implementation"));
        let wrap_tail = &source[wrap_start..];
        let wrap_end = wrap_tail
            .find("function unwrap(uint256 _wstETHAmount)")
            .unwrap_or_else(|| panic!("{label} wrap implementation end"));
        let wrap = normalized_whitespace(&wrap_tail[..wrap_end]);
        assert_fragments_in_order(
            &wrap,
            &[
                r#"require(_stETHAmount > 0, "wstETH: can't wrap zero stETH");"#,
                "uint256 wstETHAmount = stETH.getSharesByPooledEth(_stETHAmount);",
                "_mint(msg.sender, wstETHAmount);",
                "stETH.transferFrom(msg.sender, address(this), _stETHAmount);",
                "return wstETHAmount;",
            ],
        );
    }

    let abi_spec = &wrap_spec["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read wrap ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse wrap ABI");
    let entries = abi.as_array().expect("wrap ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("wrap"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    let inputs = entry["inputs"].as_array().expect("wrap ABI inputs");
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["name"].as_str(), Some("_stETHAmount"));
    assert_eq!(inputs[0]["type"].as_str(), Some("uint256"));
    let outputs = entry["outputs"].as_array().expect("wrap ABI outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"].as_str(), Some("uint256"));
    assert_eq!(
        format!(
            "{}({})",
            entry["name"].as_str().unwrap(),
            inputs[0]["type"].as_str().unwrap()
        ),
        signature
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor address")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["stETHaddress"]
            .as_str()
            .expect("stETH constant")
            .to_ascii_lowercase(),
        required_str(deployment, "constructor_argument_steth")
    );

    let format = &descriptor["display"]["formats"]["wrap(uint256 _stETHAmount)"];
    assert_eq!(format["intent"].as_str(), Some("Wrap stETH"));
    let fields = format["fields"].as_array().expect("wrap display fields");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["label"].as_str(), Some("stETH amount"));
    assert_eq!(fields[0]["path"].as_str(), Some("#._stETHAmount"));
    assert_eq!(fields[0]["format"].as_str(), Some("tokenAmount"));
    assert_eq!(fields[0]["visible"].as_str(), Some("always"));
    assert_eq!(
        fields[0]["params"]["token"].as_str(),
        Some("$.metadata.constants.stETHaddress")
    );
    let displayed_paths: Vec<_> = wrap_spec["displayed_operand_paths"]
        .as_array()
        .expect("wrap displayed paths")
        .iter()
        .map(|path| path.as_str().expect("wrap displayed path"))
        .collect();
    assert_eq!(displayed_paths, ["#._stETHAmount"]);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let steth: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(deployment, "constructor_argument_steth"))
        })
        .collect();
    assert_eq!(steth.len(), 1);
    assert_eq!(steth[0].name, "Liquid staked Ether 2.0");
    assert_eq!(steth[0].symbol, "stETH");
    assert_eq!(steth[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(registry_entry.chain_id, 1);
    assert_eq!(
        hex::encode(registry_entry.contract),
        required_str(deployment, "address").trim_start_matches("0x")
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    let format = ir
        .find_format_by_selector(&selector)
        .expect("Lido format table parses")
        .expect("Lido wrap remains admitted");
    let fields: Vec<_> = format
        .fields()
        .map(|field| field.expect("generated wrap field parses"))
        .collect();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].label, b"stETH amount");
    assert_eq!(
        FormatOp::try_from(fields[0].format_op),
        Ok(FormatOp::TokenAmount)
    );
    let params = parse_params(&ir, fields[0].param_off).expect("wrap field params parse");
    assert_eq!(params.visibility, Visibility::Always);
    assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
    assert_eq!(params.integer_width_bytes, Some(32));
    assert_eq!(
        params.token.map(hex::encode),
        Some(
            required_str(deployment, "constructor_argument_steth")
                .trim_start_matches("0x")
                .to_owned()
        )
    );

    let output_residual = required_str(wrap_spec, "output_residual");
    assert!(output_residual.contains("live stETH share state"));
    assert!(output_residual.contains("not signed calldata"));
}

#[test]
fn lido_wsteth_remaining_routes_source_abi_descriptor_and_ir_agree() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let deployment = &manifest["deployment"];
    let remaining = &manifest["additional_routes"]["remaining"];
    let routes = remaining["routes"]
        .as_array()
        .expect("remaining routes array");

    let expected_routes = BTreeMap::from([
        ("approve", "0x095ea7b3"),
        ("decreaseAllowance", "0xa457c2d7"),
        ("increaseAllowance", "0x39509351"),
        ("transfer", "0xa9059cbb"),
        ("transferFrom", "0x23b872dd"),
        ("unwrap", "0xde0e9a3e"),
    ]);
    let actual_keys: BTreeSet<_> = routes
        .iter()
        .map(|route| required_str(route, "key"))
        .collect();
    assert_eq!(
        actual_keys,
        expected_routes.keys().copied().collect(),
        "remaining route inventory drifted"
    );

    let source_spec = &manifest["verified_source"];
    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let flattened = normalized_whitespace(
        &String::from_utf8(flattened_bytes).expect("flattened source is UTF-8"),
    );
    for helper_semantics in [
        r#"function _transfer(address sender, address recipient, uint256 amount) internal virtual { require(sender != address(0), "ERC20: transfer from the zero address"); require(recipient != address(0), "ERC20: transfer to the zero address"); _beforeTokenTransfer(sender, recipient, amount); _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance"); _balances[recipient] = _balances[recipient].add(amount); emit Transfer(sender, recipient, amount); }"#,
        r#"function _burn(address account, uint256 amount) internal virtual { require(account != address(0), "ERC20: burn from the zero address"); _beforeTokenTransfer(account, address(0), amount); _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance"); _totalSupply = _totalSupply.sub(amount); emit Transfer(account, address(0), amount); }"#,
        r#"function _approve(address owner, address spender, uint256 amount) internal virtual { require(owner != address(0), "ERC20: approve from the zero address"); require(spender != address(0), "ERC20: approve to the zero address"); _allowances[owner][spender] = amount; emit Approval(owner, spender, amount); }"#,
    ] {
        assert!(flattened.contains(helper_semantics));
    }
    assert_eq!(
        flattened
            .matches("function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }")
            .count(),
        1,
        "wstETH must retain the single empty inherited transfer hook"
    );

    let runtime = read_hex(&evidence.join(required_str(&manifest["runtime"], "file")));
    let abi_spec = &remaining["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read remaining-route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    assert_eq!(
        required_str(abi_spec, "source_full_verified_abi_canonical_sha256"),
        required_str(&manifest["abi"], "full_verified_abi_canonical_sha256"),
        "remaining-route ABI subset lost its pinned full-ABI source receipt"
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse remaining-route ABI");
    let abi_entries = abi.as_array().expect("remaining-route ABI array");
    assert_eq!(abi_entries.len(), routes.len());

    let descriptor_spec = &manifest["descriptor"];
    let descriptor_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        descriptor_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor")
    );
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor deployment")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["wstETHaddress"]
            .as_str()
            .expect("wstETH token constant")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    let descriptor_formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    let contract: [u8; 20] = decode_hex_text(required_str(deployment, "address"))
        .try_into()
        .expect("wstETH contract width");
    assert_eq!(
        (registry_entry.chain_id, registry_entry.contract),
        (1, contract)
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated wstETH IR");
    assert_eq!(cross_check_contract(&ir, 1, &contract), Ok(()));

    let canonicalize = |authored: &str| {
        let (name, tail) = authored.split_once('(').expect("authored signature");
        let params = tail.strip_suffix(')').expect("signature close");
        let types: Vec<_> = params
            .split(',')
            .filter(|param| !param.trim().is_empty())
            .map(|param| {
                param
                    .split_ascii_whitespace()
                    .next()
                    .expect("authored input type")
            })
            .collect();
        format!("{name}({})", types.join(","))
    };

    for route in routes {
        let key = required_str(route, "key");
        let signature = required_str(route, "canonical_signature");
        let expected_selector = expected_routes
            .get(key)
            .unwrap_or_else(|| panic!("unexpected remaining route {key}"));
        assert_eq!(required_str(route, "selector"), *expected_selector);
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert_eq!(
            format!("0x{}", hex::encode(selector)),
            *expected_selector,
            "{key} selector drifted"
        );
        assert!(
            runtime
                .windows(selector.len())
                .any(|candidate| candidate == selector),
            "runtime lost {signature}"
        );

        let source_semantics = match key {
            "approve" => "function approve(address spender, uint256 amount) public virtual override returns (bool) { _approve(_msgSender(), spender, amount); return true; }",
            "decreaseAllowance" => r#"function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) { _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero")); return true; }"#,
            "increaseAllowance" => "function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) { _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue)); return true; }",
            "transfer" => "function transfer(address recipient, uint256 amount) public virtual override returns (bool) { _transfer(_msgSender(), recipient, amount); return true; }",
            "transferFrom" => r#"function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) { _transfer(sender, recipient, amount); _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance")); return true; }"#,
            "unwrap" => r#"function unwrap(uint256 _wstETHAmount) external returns (uint256) { require(_wstETHAmount > 0, "wstETH: zero amount unwrap not allowed"); uint256 stETHAmount = stETH.getPooledEthByShares(_wstETHAmount); _burn(msg.sender, _wstETHAmount); stETH.transfer(msg.sender, stETHAmount); return stETHAmount; }"#,
            _ => unreachable!("route inventory checked above"),
        };
        assert!(
            flattened.contains(source_semantics),
            "verified source semantics drifted for {signature}"
        );

        let descriptor_matches: Vec<_> = descriptor_formats
            .iter()
            .filter(|(authored, _)| canonicalize(authored) == signature)
            .collect();
        assert_eq!(descriptor_matches.len(), 1, "descriptor route match");
        let (authored_signature, descriptor_format) = descriptor_matches[0];
        let (_, tail) = authored_signature
            .split_once('(')
            .expect("authored signature");
        let authored_inputs: Vec<_> = tail
            .strip_suffix(')')
            .expect("signature close")
            .split(',')
            .map(|param| {
                let mut parts = param.split_ascii_whitespace();
                let input_type = parts.next().expect("descriptor input type");
                let name = parts.next().expect("descriptor input name");
                assert!(parts.next().is_none(), "unexpected descriptor input token");
                (name, input_type)
            })
            .collect();

        let abi_matches: Vec<_> = abi_entries
            .iter()
            .filter(|entry| {
                let Some(name) = entry["name"].as_str() else {
                    return false;
                };
                let Some(inputs) = entry["inputs"].as_array() else {
                    return false;
                };
                let types: Vec<_> = inputs
                    .iter()
                    .filter_map(|input| input["type"].as_str())
                    .collect();
                format!("{name}({})", types.join(",")) == signature
            })
            .collect();
        assert_eq!(abi_matches.len(), 1, "exact ABI route match");
        let abi_entry = abi_matches[0];
        assert_eq!(abi_entry["type"].as_str(), Some("function"));
        assert_eq!(abi_entry["stateMutability"].as_str(), Some("nonpayable"));
        let abi_inputs: Vec<_> = abi_entry["inputs"]
            .as_array()
            .expect("ABI inputs")
            .iter()
            .map(|input| {
                (
                    input["name"].as_str().expect("ABI input name"),
                    input["type"].as_str().expect("ABI input type"),
                )
            })
            .collect();
        assert_eq!(abi_inputs, authored_inputs, "{key} ABI operands drifted");
        let outputs = abi_entry["outputs"].as_array().expect("ABI outputs");
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0]["type"].as_str(),
            Some(if key == "unwrap" { "uint256" } else { "bool" })
        );

        let descriptor_fields = descriptor_format["fields"]
            .as_array()
            .expect("descriptor fields");
        let displayed_paths: Vec<_> = route["displayed_operand_paths"]
            .as_array()
            .expect("displayed operand paths")
            .iter()
            .map(|path| path.as_str().expect("displayed operand path"))
            .collect();
        assert_eq!(
            displayed_paths,
            descriptor_fields
                .iter()
                .map(|field| field["path"].as_str().expect("descriptor field path"))
                .collect::<Vec<_>>(),
            "{key} operand coverage drifted"
        );

        let ir_format = ir
            .find_format_by_selector(&selector)
            .expect("wstETH format table parses")
            .expect("remaining wstETH route remains admitted");
        let ir_fields: Vec<_> = ir_format
            .fields()
            .map(|field| field.expect("generated route field parses"))
            .collect();
        assert_eq!(ir_fields.len(), descriptor_fields.len());

        for (descriptor_field, ir_field) in descriptor_fields.iter().zip(ir_fields) {
            let path = descriptor_field["path"]
                .as_str()
                .expect("descriptor field path");
            let (label, op, kind) = match path {
                "#.spender" => ("Spender", FormatOp::AddressName, TerminalKind::Address),
                "#.recipient" => ("Recipient", FormatOp::AddressName, TerminalKind::Address),
                "#.sender" => ("Sender", FormatOp::AddressName, TerminalKind::Address),
                "#.amount" | "#.addedValue" | "#.subtractedValue" => {
                    ("Amount", FormatOp::TokenAmount, TerminalKind::Unsigned)
                }
                "#._wstETHAmount" => (
                    "wstETH amount",
                    FormatOp::TokenAmount,
                    TerminalKind::Unsigned,
                ),
                _ => panic!("unexpected remaining-route operand path {path}"),
            };
            assert_eq!(descriptor_field["label"].as_str(), Some(label));
            assert_eq!(descriptor_field["visible"].as_str(), Some("always"));
            assert_eq!(
                descriptor_field["format"].as_str(),
                Some(if op == FormatOp::AddressName {
                    "addressName"
                } else {
                    "tokenAmount"
                })
            );
            assert_eq!(ir_field.label, label.as_bytes());
            assert_eq!(FormatOp::try_from(ir_field.format_op), Ok(op));
            let params = parse_params(&ir, ir_field.param_off).expect("route params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(kind));
            if op == FormatOp::TokenAmount {
                assert_eq!(params.integer_width_bytes, Some(32));
                assert_eq!(
                    descriptor_field["params"]["token"].as_str(),
                    Some("$.metadata.constants.wstETHaddress")
                );
                assert_eq!(params.token.map(hex::encode), Some(hex::encode(contract)));
                let threshold_expected = matches!(
                    (key, path),
                    ("approve", "#.amount") | ("increaseAllowance", "#.addedValue")
                );
                if threshold_expected {
                    let threshold = [0xff; 32];
                    assert_eq!(
                        descriptor_field["params"]["threshold"].as_str(),
                        Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    );
                    assert_eq!(
                        descriptor_field["params"]["message"].as_str(),
                        Some("Max uint256")
                    );
                    assert_eq!(
                        params.threshold.map(|value| value.as_slice()),
                        Some(threshold.as_slice())
                    );
                    assert_eq!(params.message, Some(b"Max uint256".as_slice()));
                } else {
                    assert!(params.threshold.is_none());
                    assert!(params.message.is_none());
                }
            } else {
                assert!(params.token.is_none());
            }
        }

        let (effect_needles, residual_needles): (&[&str], &[&str]) = match key {
            "approve" => (
                &["sets", "allowance", "signed amount"],
                &["prior allowance", "ordering"],
            ),
            "decreaseAllowance" => (
                &["allowance", "minus", "signed subtractedvalue"],
                &["resulting allowances", "live state", "not signed calldata"],
            ),
            "increaseAllowance" => (
                &["allowance", "plus", "signed addedvalue"],
                &["resulting allowances", "live state", "not signed calldata"],
            ),
            "transfer" => (
                &["exactly", "msg.sender", "recipient"],
                &["balance", "success"],
            ),
            "transferFrom" => (
                &["sender", "recipient", "reduces", "allowance"],
                &[
                    "allowance",
                    "live state",
                    "neither signed calldata",
                    "nor displayed",
                ],
            ),
            "unwrap" => (
                &["burn", "wsteth", "steth"],
                &["live", "steth", "not signed calldata"],
            ),
            _ => unreachable!("route inventory checked above"),
        };
        for (field, needles) in [
            ("successful_effect", effect_needles),
            ("state_residual", residual_needles),
        ] {
            let text = required_str(route, field).to_ascii_lowercase();
            for needle in needles {
                assert!(
                    text.contains(needle),
                    "{key} {field} must record {needle:?}"
                );
            }
        }
    }
}

#[test]
fn uniswap_router02_evidence_binds_constrained_single_hop_restoration() {
    let root = workspace_root();
    let evidence = uniswap_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["policy"]["outcome"].as_str(),
        Some("constrained_restoration")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_release"].as_str(),
        Some("v1.1.0")
    );
    assert_eq!(
        manifest["verified_source"]["annotated_tag_object"].as_str(),
        Some("535ee984afa8e32a0206d372ecbc5f6186360f27")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_commit"].as_str(),
        Some("8fe4f086cee7c08f0bdb6ebe20c9ab615921c65f")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_tree"].as_str(),
        Some("84ed2b9297023bf6fce8ae90b057abf030d8c65f")
    );
    assert_eq!(
        manifest["verified_source"]
            ["archived_files_match_official_release_and_verified_explorer_sources"]
            .as_bool(),
        Some(true)
    );

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(1));
    assert_eq!(deployment["block_number"].as_u64(), Some(13_804_681));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(14));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(
        required_str(deployment, "receipt_contract_address"),
        required_str(deployment, "address")
    );
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(25_013));
    for receipt in [deployment, &manifest["evidence_block"]] {
        assert_eq!(
            receipt["rpc_endpoints"]
                .as_array()
                .expect("RPC endpoint array")
                .len(),
            2
        );
        let hash_key = if receipt.get("block_hash").is_some() {
            "block_hash"
        } else {
            "hash"
        };
        assert_eq!(decode_hex_text(required_str(receipt, hash_key)).len(), 32);
        assert_eq!(
            decode_hex_text(required_str(receipt, "state_root")).len(),
            32
        );
    }

    let contract: [u8; 20] = decode_hex_text(required_str(deployment, "address"))
        .try_into()
        .expect("Router02 address width");
    assert_eq!(
        hex::encode(contract),
        "68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
    );

    let constraints = &manifest["policy"]["constraints"];
    assert_eq!(
        constraints["recipient_router_sentinel_policy"].as_str(),
        Some("reject")
    );
    assert_eq!(
        constraints["exact_input_zero_amount_policy"].as_str(),
        Some("reject")
    );
    assert_eq!(
        constraints["nonzero_sqrt_price_limit_policy"].as_str(),
        Some("reject")
    );
    assert_eq!(
        constraints["outer_native_value_policy"].as_str(),
        Some("require_zero")
    );

    let route_specs = manifest["policy"]["constrained_routes"]
        .as_array()
        .expect("excluded route array");
    assert_eq!(route_specs.len(), 2);
    let mut expected_routes = BTreeMap::<String, [u8; 4]>::new();
    for route in route_specs {
        let signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .expect("selector width");
        assert_eq!(&keccak256(signature.as_bytes())[..4], selector.as_slice());
        expected_routes.insert(signature.to_owned(), selector);
    }
    assert_eq!(
        expected_routes,
        BTreeMap::from([
            (
                "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
                    .to_owned(),
                [0x04, 0xe4, 0x5a, 0xaf],
            ),
            (
                "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
                    .to_owned(),
                [0x50, 0x23, 0xb4, 0xdf],
            ),
        ])
    );

    let runtime_spec = &manifest["runtime"];
    let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().expect("runtime byte count")
    );
    assert_eq!(sha256_hex(&runtime), required_str(runtime_spec, "sha256"));
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    for (signature, selector) in &expected_routes {
        assert!(
            runtime
                .windows(selector.len())
                .any(|window| window == selector),
            "archived runtime lost {signature}"
        );
    }
    for (slot_key, value_key) in [
        (
            "eip1967_implementation_slot",
            "eip1967_implementation_slot_value",
        ),
        ("eip1967_beacon_slot", "eip1967_beacon_slot_value"),
    ] {
        assert_eq!(
            decode_hex_text(required_str(runtime_spec, slot_key)).len(),
            32
        );
        assert_eq!(
            decode_hex_text(required_str(runtime_spec, value_key)),
            [0u8; 32]
        );
    }

    let source_spec = &manifest["verified_source"];
    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in source_spec["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(sha256_hex(&bytes), required_str(source, "sha256"));
        archived_sources.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("Solidity source is UTF-8"),
        );
    }
    assert_eq!(archived_sources.len(), 6);

    let concrete = normalized_whitespace(&archived_sources["source/SwapRouter02.sol"]);
    assert!(concrete.contains(
        "contract SwapRouter02 is ISwapRouter02, V2SwapRouter, V3SwapRouter, ApproveAndCall, MulticallExtended, SelfPermit"
    ));

    let constants = normalized_whitespace(&archived_sources["source/Constants.sol"]);
    assert!(constants.contains("uint256 internal constant CONTRACT_BALANCE = 0;"));
    assert!(constants.contains("address internal constant MSG_SENDER = address(1);"));
    assert!(constants.contains("address internal constant ADDRESS_THIS = address(2);"));

    let interface = normalized_whitespace(&archived_sources["source/IV3SwapRouter.sol"]);
    assert!(interface
        .contains("Setting `amountIn` to 0 will cause the contract to look up its own balance"));
    assert!(interface.contains(
        "function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);"
    ));
    assert!(interface.contains(
        "function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);"
    ));

    let router = normalized_whitespace(&archived_sources["source/V3SwapRouter.sol"]);
    assert!(router.matches(
        "if (recipient == Constants.MSG_SENDER) recipient = msg.sender; else if (recipient == Constants.ADDRESS_THIS) recipient = address(this);"
    ).count() >= 2);
    assert_fragments_in_order(
        &router,
        &[
            "function exactInputSingle(ExactInputSingleParams memory params)",
            "if (params.amountIn == Constants.CONTRACT_BALANCE) {",
            "params.amountIn = IERC20(params.tokenIn).balanceOf(address(this));",
            "payer: hasAlreadyPaid ? address(this) : msg.sender",
            "require(amountOut >= params.amountOutMinimum, 'Too little received');",
        ],
    );

    let payment_dependency = &manifest["payment_dependency"];
    for key in [
        "swap_router_package",
        "swap_router_lock",
        "v3_periphery_source",
    ] {
        let receipt = &payment_dependency[key];
        let bytes = fs::read(evidence.join(required_str(receipt, "archive_file")))
            .unwrap_or_else(|error| panic!("read Uniswap dependency {key}: {error}"));
        assert_eq!(sha256_hex(&bytes), required_str(receipt, "sha256"));
    }
    assert_eq!(
        payment_dependency["swap_router_package"]["declared_dependency"].as_str(),
        Some("@uniswap/v3-periphery@1.3.0")
    );
    assert_eq!(
        payment_dependency["v3_periphery_source"]["upstream_commit"].as_str(),
        Some("80f26c86c57b8a5e4b913f42844d4c8bd274d058")
    );
    assert_eq!(
        payment_dependency["v3_periphery_source"]["locked_tarball_file_sha256"].as_str(),
        payment_dependency["v3_periphery_source"]["sha256"].as_str()
    );
    let payments = normalized_whitespace(
        &fs::read_to_string(evidence.join(required_str(
            &payment_dependency["v3_periphery_source"],
            "archive_file",
        )))
        .expect("read pinned PeripheryPayments source"),
    );
    assert_fragments_in_order(
        &payments,
        &[
            "function pay(",
            "if (token == WETH9 && address(this).balance >= value)",
            "IWETH9(WETH9).deposit{value: value}();",
            "else if (payer == address(this))",
            "TransferHelper.safeTransfer(token, recipient, value);",
            "TransferHelper.safeTransferFrom(token, payer, recipient, value);",
        ],
    );
    assert_fragments_in_order(
        &router,
        &[
            "function exactOutputInternal(",
            "uint256 amountOutReceived;",
            "(amountIn, amountOutReceived) =",
            "if (sqrtPriceLimitX96 == 0) require(amountOutReceived == amountOut);",
            "function exactOutputSingle(ExactOutputSingleParams calldata params)",
            "require(amountIn <= params.amountInMaximum, 'Too much requested');",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read Router02 ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse Router02 ABI");
    let entries = abi.as_array().expect("Router02 ABI array");
    assert_eq!(entries.len(), 2);
    let mut abi_signatures = BTreeSet::new();
    for entry in entries {
        assert_eq!(entry["type"].as_str(), Some("function"));
        assert_eq!(entry["stateMutability"].as_str(), Some("payable"));
        let inputs = entry["inputs"].as_array().expect("route ABI inputs");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["name"].as_str(), Some("params"));
        assert_eq!(inputs[0]["type"].as_str(), Some("tuple"));
        let component_types: Vec<_> = inputs[0]["components"]
            .as_array()
            .expect("tuple components")
            .iter()
            .map(|component| component["type"].as_str().expect("component type"))
            .collect();
        assert_eq!(
            component_types,
            ["address", "address", "uint24", "address", "uint256", "uint256", "uint160"]
        );
        let signature = format!(
            "{}(({}))",
            entry["name"].as_str().expect("function name"),
            component_types.join(",")
        );
        assert!(expected_routes.contains_key(&signature));
        abi_signatures.insert(signature);
        let outputs = entry["outputs"].as_array().expect("route ABI outputs");
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["type"].as_str(), Some("uint256"));
    }
    assert_eq!(
        abi_signatures,
        expected_routes.keys().cloned().collect::<BTreeSet<_>>()
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Router02 descriptor");
    assert_eq!(
        sha256_hex(&curated_bytes),
        required_str(descriptor_spec, "sha256")
    );
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Router02 descriptor"),
        "curated and installed Router02 descriptors diverged"
    );
    let descriptor: Value =
        serde_json::from_slice(&curated_bytes).expect("parse Router02 descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert!(deployments.iter().any(|candidate| {
        candidate["chainId"].as_u64() == Some(1)
            && candidate["address"].as_str().is_some_and(|address| {
                address.eq_ignore_ascii_case(required_str(deployment, "address"))
            })
    }));
    let sentinel = required_str(descriptor_spec, "sender_address_sentinel");
    for route in route_specs {
        let format_key = required_str(route, "descriptor_format_key");
        let fields = descriptor["display"]["formats"][format_key]["fields"]
            .as_array()
            .expect("single-hop display fields");
        let recipients: Vec<_> = fields
            .iter()
            .filter(|field| field["path"].as_str() == Some("params.recipient"))
            .collect();
        assert_eq!(recipients.len(), 1);
        let sender_addresses = recipients[0]["params"]["senderAddress"]
            .as_array()
            .expect("senderAddress annotation");
        assert_eq!(sender_addresses.len(), 1);
        assert_eq!(sender_addresses[0].as_str(), Some(sentinel));

        let value_fields: Vec<_> = fields
            .iter()
            .filter(|field| field["path"].as_str() == Some("@.value"))
            .collect();
        assert_eq!(value_fields.len(), 1);
        assert_eq!(value_fields[0]["label"].as_str(), Some("Native value"));
        assert_eq!(value_fields[0]["format"].as_str(), Some("amount"));
        assert_eq!(value_fields[0]["visible"].as_str(), Some("always"));
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let router_entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-UniswapV3Router02.json")
        })
        .collect();
    assert_eq!(
        router_entries.len(),
        1,
        "one exact Router02 deployment leaf"
    );
    let ir = Erc7730Ir::parse(&router_entries[0].ir_bytes).expect("parse restored Router02 IR");
    assert_eq!(ir.format_count(), Ok(2));
    for (signature, selector) in expected_routes {
        assert!(
            ir.find_format_by_selector(&selector)
                .expect("Router02 format table parses")
                .is_some(),
            "{signature} must be present under constrained restoration"
        );
        assert!(
            registry.known_calls.contains(&(1, contract, selector)),
            "{signature} must remain an exact known-call tuple"
        );
    }
}

#[test]
fn lido_queue_evidence_pins_upgradeable_proxy_and_official_sources() {
    let evidence = lido_queue_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["upstream"]["repository"].as_str(),
        Some("https://github.com/lidofinance/core")
    );
    assert_eq!(manifest["upstream"]["release"].as_str(), Some("v2.0.0"));
    assert_eq!(
        manifest["upstream"]["commit"].as_str(),
        Some("cadffa46a2b8ed6cfa1127fca2468bae1a82d6bf")
    );
    assert_eq!(
        manifest["upstream"]["tree"].as_str(),
        Some("96c71e4f4e342f54e3f16a37d1a526fe25caa40b")
    );

    for source in manifest["upstream"]["files"]
        .as_array()
        .expect("official source array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read official Lido source");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(source, "sha256"),
            "official source hash drifted for {archive_file}"
        );
    }

    let deployment_spec = &manifest["upstream"]["deployment_record"];
    let deployment_bytes = fs::read(evidence.join(required_str(deployment_spec, "archive_file")))
        .expect("read official deployment record");
    assert_eq!(
        sha256_hex(&deployment_bytes),
        required_str(deployment_spec, "sha256")
    );
    let deployment: Value =
        serde_json::from_slice(&deployment_bytes).expect("parse official deployment record");
    let deployed = &deployment["withdrawalQueueERC721"];
    assert!(deployed["proxy"]["address"]
        .as_str()
        .expect("proxy address")
        .eq_ignore_ascii_case(required_str(&manifest["deployment"], "proxy_address")));
    assert!(deployed["implementation"]["address"]
        .as_str()
        .expect("implementation address")
        .eq_ignore_ascii_case(required_str(
            &manifest["deployment"],
            "implementation_address_at_fixed_block"
        )));
    assert_eq!(
        deployed["implementation"]["constructorArgs"][1].as_str(),
        Some("Lido: stETH Withdrawal NFT")
    );
    assert_eq!(
        deployed["implementation"]["constructorArgs"][2].as_str(),
        Some("unstETH")
    );

    let receipt_spec = &manifest["deployment"]["fixed_block"];
    let receipt_bytes = fs::read(evidence.join(required_str(receipt_spec, "receipt_file")))
        .expect("read fixed-block RPC receipt");
    assert_eq!(
        sha256_hex(&receipt_bytes),
        required_str(receipt_spec, "receipt_file_sha256")
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("parse RPC receipt");
    assert_eq!(receipt["schema_version"].as_u64(), Some(1));
    assert_eq!(receipt["chain_id"].as_u64(), Some(1));
    let observations = receipt["observations"]
        .as_array()
        .expect("independent RPC observations");
    assert_eq!(observations.len(), 2);
    let expected_endpoints: BTreeSet<_> = receipt_spec["rpc_endpoints"]
        .as_array()
        .expect("manifest RPC endpoints")
        .iter()
        .map(|endpoint| endpoint.as_str().expect("RPC endpoint"))
        .collect();
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation["endpoint"].as_str().expect("RPC endpoint"))
            .collect::<BTreeSet<_>>(),
        expected_endpoints
    );
    for observation in observations {
        for key in [
            "hash",
            "number",
            "number_hex",
            "state_root",
            "timestamp",
            "timestamp_utc",
        ] {
            assert_eq!(
                observation["block"][key], receipt_spec[key],
                "fixed-block field {key} disagrees"
            );
        }
        assert!(observation["calls"]["proxy__getImplementation"]["decoded"]
            .as_str()
            .expect("decoded implementation")
            .eq_ignore_ascii_case(required_str(
                &manifest["deployment"],
                "implementation_address_at_fixed_block"
            )));
        assert!(observation["calls"]["proxy__getAdmin"]["decoded"]
            .as_str()
            .expect("decoded admin")
            .eq_ignore_ascii_case(required_str(
                &manifest["deployment"],
                "proxy_admin_at_fixed_block"
            )));
        assert_eq!(
            observation["calls"]["proxy__getIsOssified"]["decoded"].as_bool(),
            Some(false)
        );
    }
    assert_eq!(
        manifest["deployment"]["proxy_ossified_at_fixed_block"].as_bool(),
        Some(false)
    );

    for (name, spec) in manifest["runtime_artifacts"]
        .as_object()
        .expect("runtime artifact map")
    {
        let artifact = fs::read(evidence.join(required_str(spec, "file")))
            .expect("read archived runtime artifact");
        assert_eq!(
            sha256_hex(&artifact),
            required_str(spec, "artifact_sha256"),
            "{name} artifact hash drifted"
        );
        let runtime = decode_hex_text(&String::from_utf8(artifact).expect("runtime hex is UTF-8"));
        assert_eq!(
            runtime.len() as u64,
            spec["bytes"].as_u64().expect("runtime byte count")
        );
        assert_eq!(keccak_hex(&runtime), required_str(spec, "keccak256"));
        for observation in observations {
            assert_eq!(
                observation["code"][name]["bytes"], spec["bytes"],
                "{name} RPC byte count disagrees"
            );
            assert_eq!(
                observation["code"][name]["keccak256"], spec["keccak256"],
                "{name} RPC code hash disagrees"
            );
        }
    }

    let proxy = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/OssifiableProxy.sol"))
            .expect("read official proxy source"),
    );
    assert!(proxy.contains(
        "function proxy__upgradeTo(address newImplementation_) external onlyAdmin { _upgradeTo(newImplementation_); }"
    ));
    assert!(proxy.contains(
        "modifier onlyAdmin() { address admin = _getAdmin(); if (admin == address(0)) { revert ProxyIsOssified(); }"
    ));
    assert!(manifest["residuals"]
        .as_array()
        .expect("evidence residuals")
        .iter()
        .any(|residual| residual
            .as_str()
            .is_some_and(|text| text.contains("admin-upgradeable"))));
}

#[test]
fn lido_queue_source_abi_descriptor_and_ir_agree_on_seven_admitted_routes() {
    let root = workspace_root();
    let evidence = lido_queue_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let routes = manifest["routes"].as_array().expect("Lido route array");
    assert_eq!(routes.len(), 7);

    let expected = BTreeMap::from([
        (
            "approve(address,uint256)",
            (
                "admitted",
                vec![
                    ("Approval target", "#._to", "addressName"),
                    ("Request ID", "#._requestId", "raw"),
                ],
            ),
        ),
        (
            "claimWithdrawal(uint256)",
            ("admitted", vec![("Request ID", "#._requestId", "raw")]),
        ),
        (
            "safeTransferFrom(address,address,uint256)",
            (
                "admitted",
                vec![
                    ("From", "#._from", "addressName"),
                    ("To", "#._to", "addressName"),
                    ("Request ID", "#._requestId", "raw"),
                ],
            ),
        ),
        (
            "setApprovalForAll(address,bool)",
            (
                "admitted",
                vec![
                    ("Operator", "#._operator", "addressName"),
                    ("Access rights", "#._approved", "enum"),
                ],
            ),
        ),
        (
            "transferFrom(address,address,uint256)",
            (
                "admitted",
                vec![
                    ("From", "#._from", "addressName"),
                    ("To", "#._to", "addressName"),
                    ("Request ID", "#._requestId", "raw"),
                ],
            ),
        ),
        (
            "requestWithdrawals(uint256[],address)",
            (
                "admitted",
                vec![
                    ("Amount", "#._amounts.[]", "tokenAmount"),
                    ("Initial NFT owner", "#._owner", "addressName"),
                ],
            ),
        ),
        (
            "requestWithdrawalsWstETH(uint256[],address)",
            (
                "admitted",
                vec![
                    ("Amount to withdraw", "#._amounts.[]", "tokenAmount"),
                    ("Beneficiary", "#._owner", "addressName"),
                ],
            ),
        ),
    ]);
    assert_eq!(
        routes
            .iter()
            .map(|route| required_str(route, "canonical_signature"))
            .collect::<BTreeSet<_>>(),
        expected.keys().copied().collect()
    );
    for route in routes {
        let signature = required_str(route, "canonical_signature");
        assert_eq!(
            required_str(route, "selector"),
            format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
        );
        assert_eq!(
            required_str(route, "status"),
            expected.get(signature).expect("known Lido route").0
        );
    }

    let source_files: BTreeMap<_, _> = manifest["upstream"]["files"]
        .as_array()
        .expect("official source array")
        .iter()
        .map(|source| {
            let file = required_str(source, "archive_file");
            (
                file,
                normalized_whitespace(
                    &fs::read_to_string(evidence.join(file)).expect("read official source"),
                ),
            )
        })
        .collect();
    let queue = &source_files["source/WithdrawalQueue.sol"];
    assert_fragments_in_order(
        queue,
        &[
            "function requestWithdrawals(uint256[] calldata _amounts, address _owner)",
            "if (_owner == address(0)) _owner = msg.sender;",
            "requestIds = new uint256[](_amounts.length);",
            "_checkWithdrawalRequestAmount(_amounts[i]);",
            "requestIds[i] = _requestWithdrawal(_amounts[i], _owner);",
        ],
    );
    assert_fragments_in_order(
        queue,
        &[
            "function requestWithdrawalsWstETH(uint256[] calldata _amounts, address _owner)",
            "if (_owner == address(0)) _owner = msg.sender;",
            "requestIds = new uint256[](_amounts.length);",
            "requestIds[i] = _requestWithdrawalWstETH(_amounts[i], _owner);",
        ],
    );
    assert_fragments_in_order(
        queue,
        &[
            "function _requestWithdrawal(uint256 _amountOfStETH, address _owner)",
            "STETH.transferFrom(msg.sender, address(this), _amountOfStETH);",
            "uint256 amountOfShares = STETH.getSharesByPooledEth(_amountOfStETH);",
            "requestId = _enqueue(uint128(_amountOfStETH), uint128(amountOfShares), _owner);",
            "_emitTransfer(address(0), _owner, requestId);",
        ],
    );
    assert_fragments_in_order(
        queue,
        &[
            "function _requestWithdrawalWstETH(uint256 _amountOfWstETH, address _owner)",
            "WSTETH.transferFrom(msg.sender, address(this), _amountOfWstETH);",
            "uint256 amountOfStETH = WSTETH.unwrap(_amountOfWstETH);",
            "_checkWithdrawalRequestAmount(amountOfStETH);",
            "uint256 amountOfShares = STETH.getSharesByPooledEth(amountOfStETH);",
            "requestId = _enqueue(uint128(amountOfStETH), uint128(amountOfShares), _owner);",
            "_emitTransfer(address(0), _owner, requestId);",
        ],
    );
    assert!(queue.contains(
        "function claimWithdrawal(uint256 _requestId) external { _claim(_requestId, _findCheckpointHint(_requestId, 1, getLastCheckpointIndex()), msg.sender); _emitTransfer(msg.sender, address(0), _requestId); }"
    ));
    let nft = &source_files["source/WithdrawalQueueERC721.sol"];
    assert_fragments_in_order(
        nft,
        &[
            "function approve(address _to, uint256 _requestId) external override",
            "_approve(_to, _requestId);",
            "function setApprovalForAll(address _operator, bool _approved) external override",
            "_setApprovalForAll(msg.sender, _operator, _approved);",
            "function safeTransferFrom(address _from, address _to, uint256 _requestId) external override",
            "safeTransferFrom(_from, _to, _requestId, \"\");",
            "function transferFrom(address _from, address _to, uint256 _requestId) external override",
            "_transfer(_from, _to, _requestId);",
        ],
    );
    assert_fragments_in_order(
        nft,
        &[
            "function _transfer(address _from, address _to, uint256 _requestId) internal",
            "delete _getTokenApprovals()[_requestId];",
            "request.owner = _to;",
            "_emitTransfer(_from, _to, _requestId);",
            "function _approve(address _to, uint256 _requestId) internal",
            "_getTokenApprovals()[_requestId] = _to;",
            "function _setApprovalForAll(address _owner, address _operator, bool _approved) internal",
            "_getOperatorApprovals()[_owner][_operator] = _approved;",
        ],
    );
    let base = &source_files["source/WithdrawalQueueBase.sol"];
    assert_fragments_in_order(
        base,
        &[
            "function _claim(uint256 _requestId, uint256 _hint, address _recipient) internal",
            "if (request.owner != msg.sender) revert NotOwner(msg.sender, request.owner);",
            "request.claimed = true;",
            "uint256 ethWithDiscount = _calculateClaimableEther(request, _requestId, _hint);",
            "_sendValue(_recipient, ethWithDiscount);",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read Lido route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse Lido route ABI");
    let abi_entries = abi.as_array().expect("Lido ABI array");
    assert_eq!(abi_entries.len(), routes.len());
    let abi_signatures: BTreeSet<_> = abi_entries
        .iter()
        .map(|entry| {
            assert_eq!(entry["type"].as_str(), Some("function"));
            assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
            format!(
                "{}({})",
                entry["name"].as_str().expect("ABI function name"),
                entry["inputs"]
                    .as_array()
                    .expect("ABI inputs")
                    .iter()
                    .map(|input| input["type"].as_str().expect("ABI input type"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect();
    assert_eq!(
        abi_signatures,
        expected.keys().map(|key| (*key).to_owned()).collect()
    );

    let curated = root.join(
        "secure/data/erc7730/curations/files/registry/lido/calldata-WithdrawalQueueERC721.json",
    );
    let vendored =
        root.join("secure/data/erc7730-registry/registry/lido/calldata-WithdrawalQueueERC721.json");
    let descriptor_bytes = fs::read(&curated).expect("read curated Lido descriptor");
    assert_eq!(
        descriptor_bytes,
        fs::read(&vendored).expect("read vendored Lido descriptor"),
        "curated and installed Lido queue descriptors diverged"
    );
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse Lido queue descriptor");
    let deployment = &descriptor["context"]["contract"]["deployments"][0];
    assert_eq!(deployment["chainId"].as_u64(), Some(1));
    assert!(deployment["address"]
        .as_str()
        .expect("descriptor deployment")
        .eq_ignore_ascii_case(required_str(&manifest["deployment"], "proxy_address")));
    assert_eq!(
        descriptor["metadata"]["enums"]["operatorApproval"]["0"].as_str(),
        Some("Revoke all")
    );
    assert_eq!(
        descriptor["metadata"]["enums"]["operatorApproval"]["1"].as_str(),
        Some("Grant all")
    );

    let canonicalize = |authored: &str| {
        let (name, tail) = authored.split_once('(').expect("authored signature");
        let params = tail.strip_suffix(')').expect("signature close");
        let types = params
            .split(',')
            .filter(|param| !param.trim().is_empty())
            .map(|param| param.split_ascii_whitespace().next().expect("input type"))
            .collect::<Vec<_>>();
        format!("{name}({})", types.join(","))
    };
    let descriptor_formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");
    for (signature, (_, expected_fields)) in &expected {
        let matches: Vec<_> = descriptor_formats
            .iter()
            .filter(|(authored, _)| canonicalize(authored) == *signature)
            .collect();
        assert_eq!(matches.len(), 1, "exact descriptor route {signature}");
        let fields = matches[0].1["fields"]
            .as_array()
            .expect("descriptor fields");
        assert_eq!(fields.len(), expected_fields.len());
        for (field, (label, path, format)) in fields.iter().zip(expected_fields) {
            assert_eq!(field["label"].as_str(), Some(*label));
            assert_eq!(field["path"].as_str(), Some(*path));
            assert_eq!(field["format"].as_str(), Some(*format));
        }
    }
    for signature in [
        "requestWithdrawals(uint256[],address)",
        "requestWithdrawalsWstETH(uint256[],address)",
    ] {
        let request = descriptor_formats
            .iter()
            .find(|(authored, _)| canonicalize(authored) == signature)
            .unwrap_or_else(|| panic!("{signature} descriptor format"))
            .1;
        assert_eq!(
            request["fields"][1]["params"]["senderAddress"][0].as_str(),
            Some("0x0000000000000000000000000000000000000000")
        );
    }

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let registry_root = root.join("secure/data/erc7730-registry");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-WithdrawalQueueERC721.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let entry = entries[0];
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Lido queue IR parses");
    let admitted_selectors: BTreeSet<_> = routes
        .iter()
        .filter(|route| required_str(route, "status") == "admitted")
        .map(|route| {
            decode_hex_text(required_str(route, "selector"))
                .try_into()
                .expect("selector width")
        })
        .collect();
    assert_eq!(
        ir.format_iter()
            .map(|format| format.expect("Lido queue format parses").selector)
            .collect::<BTreeSet<_>>(),
        admitted_selectors
    );
    for route in routes {
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .expect("selector width");
        assert_eq!(
            ir.find_format_by_selector(&selector)
                .expect("Lido queue format table parses")
                .is_some(),
            required_str(route, "status") == "admitted"
        );
        assert!(
            registry
                .known_calls
                .contains(&(entry.chain_id, entry.contract, selector)),
            "{} must remain an exact known-call tuple",
            required_str(route, "canonical_signature")
        );
    }

    let sender_zero = [0u8; 20];
    for signature in [
        "requestWithdrawals(uint256[],address)",
        "requestWithdrawalsWstETH(uint256[],address)",
    ] {
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        let format = ir
            .find_format_by_selector(&selector)
            .expect("Lido queue format table parses")
            .expect("request route is admitted");
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("request field parses"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(
            FormatOp::try_from(fields[0].format_op),
            Ok(FormatOp::TokenAmount)
        );
        assert_eq!(
            ir.path_bytes(fields[0].path_off)
                .expect("request amount path parses"),
            [
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::ArrayAll as u8,
            ]
        );
        let amount = parse_params(&ir, fields[0].param_off).expect("amount params parse");
        assert_eq!(amount.visibility, Visibility::Always);
        assert_eq!(amount.terminal_kind, Some(TerminalKind::Unsigned));
        assert!(amount.sender_addresses.is_none());

        assert_eq!(
            FormatOp::try_from(fields[1].format_op),
            Ok(FormatOp::AddressName)
        );
        assert_eq!(
            ir.path_bytes(fields[1].path_off)
                .expect("request owner path parses"),
            [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 1,]
        );
        let owner = parse_params(&ir, fields[1].param_off).expect("owner params parse");
        assert_eq!(owner.visibility, Visibility::Always);
        assert_eq!(owner.terminal_kind, Some(TerminalKind::Address));
        assert_eq!(owner.sender_addresses, Some(sender_zero.as_slice()));
    }
}

#[test]
fn allowance_sources_fixed_deployments_descriptors_and_ir_agree() {
    let root = workspace_root();
    let evidence = allowance_threshold_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["sources"][0]["commit"].as_str(),
        Some("0a9a7260344e671f62087547cb3c0cf49b464986")
    );
    assert_eq!(
        manifest["sources"][0]["openzeppelin_version"].as_str(),
        Some("5.0.2")
    );

    let receipt_spec = &manifest["fixed_block_receipt"];
    assert_eq!(
        required_str(receipt_spec, "sha256"),
        "8d2ba0c0322713ca793c752cb1100c61a39a69e49adef4bc72e2f21a2f40c531"
    );
    let receipt_bytes = fs::read(evidence.join(required_str(receipt_spec, "file")))
        .expect("read allowance fixed-block receipt");
    assert_eq!(
        sha256_hex(&receipt_bytes),
        required_str(receipt_spec, "sha256")
    );
    let receipt: Value =
        serde_json::from_slice(&receipt_bytes).expect("parse allowance fixed-block receipt");
    assert_eq!(receipt["blocks"].as_array().map(Vec::len), Some(7));
    assert_eq!(receipt["deployments"].as_array().map(Vec::len), Some(8));

    let deployment_set: BTreeSet<_> = receipt["deployments"]
        .as_array()
        .expect("allowance deployment array")
        .iter()
        .map(|deployment| {
            (
                required_str(deployment, "family").to_owned(),
                deployment["chain_id"].as_u64().expect("deployment chain"),
                deployment["proxy"]
                    .as_str()
                    .or_else(|| deployment["address"].as_str())
                    .expect("deployment address")
                    .to_ascii_lowercase(),
                deployment["implementation"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase(),
            )
        })
        .collect();
    let expected_deployments: BTreeSet<_> = [
        (
            "WCT",
            1,
            "0xef4461891dfb3ac8572ccf7c794664a8dd927945",
            "0xf27d4fb3b1c194f94b9966cc75b4bbb686008c8c",
        ),
        (
            "WCT",
            10,
            "0xef4461891dfb3ac8572ccf7c794664a8dd927945",
            "0x46a4c6bada93ac565b7ef6d7d9be24ca09735e22",
        ),
        (
            "WCT",
            8_453,
            "0xef4461891dfb3ac8572ccf7c794664a8dd927945",
            "0x1b9fc26a506b8cc98f65de60f337c43f97bb2d40",
        ),
        (
            "FlyingTulip",
            1,
            "0xbe4050a73a7fb384c65e885a15c33461a4b20055",
            "0xaa3d5fc84b43219391539714be5f0681aefca23b",
        ),
        (
            "FlyingTulip",
            146,
            "0xbe4050a73a7fb384c65e885a15c33461a4b20055",
            "0xaa3d5fc84b43219391539714be5f0681aefca23b",
        ),
        (
            "FlyingTulip",
            146,
            "0x82ffb119eeed117bae7a2cf38ce52eaba3871821",
            "0xb47e68e861a1661ac7f0f033b98f641a2fe565b9",
        ),
        ("USDT", 1, "0xdac17f958d2ee523a2206206994597c13d831ec7", ""),
        (
            "USDT",
            137,
            "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
            "0x90040487a6c9f949c4f07cadcfb0f3b8eeab4229",
        ),
    ]
    .into_iter()
    .map(|(family, chain, address, implementation)| {
        (
            family.to_owned(),
            chain,
            address.to_owned(),
            implementation.to_owned(),
        )
    })
    .collect();
    assert_eq!(deployment_set, expected_deployments);

    let deprecated = receipt["blocks"]
        .as_array()
        .expect("allowance block array")
        .iter()
        .find(|block| {
            block["purpose"].as_str() == Some("USDT") && block["chain_id"].as_u64() == Some(1)
        })
        .expect("Ethereum USDT fixed block");
    assert_eq!(
        deprecated["deprecated_call_result"].as_str(),
        Some("0x0000000000000000000000000000000000000000000000000000000000000000")
    );

    let source_specs = manifest["sources"]
        .as_array()
        .expect("allowance source array");
    assert_eq!(source_specs.len(), 4);
    for source in source_specs {
        let excerpt = evidence.join(required_str(source, "excerpt"));
        let bytes = fs::read(&excerpt)
            .unwrap_or_else(|error| panic!("read {}: {error}", excerpt.display()));
        assert_eq!(
            sha256_hex(&bytes),
            required_str(source, "excerpt_sha256"),
            "allowance source excerpt drifted: {}",
            excerpt.display()
        );
    }

    let wct = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/WCT.ERC20Upgradeable.allowance.excerpt.sol"))
            .expect("read WCT allowance source excerpt"),
    );
    assert_fragments_in_order(
        &wct,
        &[
            "function _spendAllowance(address owner, address spender, uint256 value)",
            "if (currentAllowance != type(uint256).max)",
            "_approve(owner, spender, currentAllowance - value, false);",
        ],
    );
    let flying_tulip = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/PositionsManager.allowance.excerpt.sol"))
            .expect("read FlyingTulip allowance source excerpt"),
    );
    assert!(flying_tulip.contains("if (allowance == type(uint256).max) return;"));
    assert!(flying_tulip
        .contains("borrowAllowance[user][msg.sender][borrowAsset] = allowance - borrowAmount;"));
    let ethereum_usdt = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/TetherToken.ethereum.allowance.excerpt.sol"))
            .expect("read Ethereum USDT allowance source excerpt"),
    );
    assert!(ethereum_usdt.contains("uint public constant MAX_UINT = 2**256 - 1;"));
    assert!(ethereum_usdt.contains("if (_allowance < MAX_UINT)"));
    let polygon_usdt = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/UChildUSDT0.polygon.allowance.excerpt.sol"))
            .expect("read Polygon USDT allowance source excerpt"),
    );
    assert!(polygon_usdt.contains(
        "_approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, \"ERC20: transfer amount exceeds allowance\"));"
    ));

    for descriptor in manifest["descriptors"]
        .as_array()
        .expect("allowance descriptor array")
    {
        let path = root.join(required_str(descriptor, "path"));
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(sha256_hex(&bytes), required_str(descriptor, "sha256"));
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    for (source, signature, label, threshold, message, expected_entries) in [
        (
            "calldata-wct.json",
            "approve(address,uint256)",
            b"Amount".as_slice(),
            Some([0xff; 32]),
            None,
            3usize,
        ),
        (
            "calldata-usdt.json",
            "approve(address,uint256)",
            b"Amount".as_slice(),
            None,
            None,
            2usize,
        ),
        (
            "calldata-PositionsManager.json",
            "approveBorrow(address,address,uint256)",
            b"Allowance".as_slice(),
            None,
            None,
            3usize,
        ),
        (
            "calldata-PositionsManager.json",
            "approveEngine(address,address,uint256)",
            b"Allowance".as_slice(),
            Some([0xff; 32]),
            Some(b"Unlimited".as_slice()),
            3usize,
        ),
    ] {
        let entries: Vec<_> = registry
            .entries
            .iter()
            .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(source))
            .collect();
        assert_eq!(
            entries.len(),
            expected_entries,
            "deployment count for {source}"
        );
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("allowance selector width");
        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse allowance IR");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("allowance format table parses")
                .unwrap_or_else(|| panic!("missing allowance format {signature}"));
            let field = format
                .fields()
                .map(|field| field.expect("allowance field parses"))
                .find(|field| field.label == label)
                .unwrap_or_else(|| panic!("missing allowance field for {signature}"));
            assert_eq!(
                FormatOp::try_from(field.format_op),
                Ok(FormatOp::TokenAmount)
            );
            let params = parse_params(&ir, field.param_off).expect("allowance params parse");
            assert_eq!(
                params.threshold.copied(),
                threshold,
                "threshold for {signature}"
            );
            assert_eq!(params.message, message, "message for {signature}");
        }
    }
}

#[test]
fn quickswap_router02_evidence_binds_static_remove_liquidity_admission() {
    let root = workspace_root();
    let evidence = quickswap_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["policy"]["outcome"].as_str(),
        Some("constrained_admission")
    );

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(137));
    assert_eq!(deployment["block_number"].as_u64(), Some(4_931_900));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(7));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(22_398));
    assert!(required_str(deployment, "receipt_contract_address")
        .eq_ignore_ascii_case(required_str(deployment, "address")));
    let contract: [u8; 20] = decode_hex_text(required_str(deployment, "address"))
        .try_into()
        .expect("QuickSwap address width");

    let admitted_specs = manifest["policy"]["admitted_routes"]
        .as_array()
        .expect("admitted route array");
    assert_eq!(admitted_specs.len(), 3);
    let mut admitted = BTreeMap::<String, [u8; 4]>::new();
    for route in admitted_specs {
        let signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .expect("QuickSwap selector width");
        assert_eq!(&keccak256(signature.as_bytes())[..4], selector.as_slice());
        admitted.insert(signature.to_owned(), selector);
    }
    assert_eq!(
        admitted,
        BTreeMap::from([
            (
                "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)"
                    .to_owned(),
                [0xba, 0xa2, 0xab, 0xde],
            ),
            (
                "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)"
                    .to_owned(),
                [0x02, 0x75, 0x1c, 0xec],
            ),
            (
                "removeLiquidityETHSupportingFeeOnTransferTokens(address,uint256,uint256,uint256,address,uint256)"
                    .to_owned(),
                [0xaf, 0x29, 0x79, 0xeb],
            ),
        ])
    );

    let runtime_spec = &manifest["runtime"];
    let runtime_file = evidence.join(required_str(runtime_spec, "file"));
    let runtime_text = fs::read(&runtime_file).expect("read QuickSwap runtime text");
    assert_eq!(
        sha256_hex(&runtime_text),
        required_str(runtime_spec, "file_sha256")
    );
    let runtime = read_hex(&runtime_file);
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().unwrap()
    );
    assert_eq!(sha256_hex(&runtime), required_str(runtime_spec, "sha256"));
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    assert!(!runtime.starts_with(&[0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73]));
    for (signature, selector) in &admitted {
        assert!(
            runtime.windows(4).any(|window| window == selector),
            "deployed runtime lost {signature}"
        );
    }
    for key in [
        "eip1967_implementation_slot_value",
        "eip1967_admin_slot_value",
        "eip1967_beacon_slot_value",
    ] {
        assert_eq!(decode_hex_text(required_str(runtime_spec, key)), [0u8; 32]);
    }

    let evidence_block = &manifest["evidence_block"];
    assert_eq!(evidence_block["number"].as_u64(), Some(90_561_024));
    let rpc_path = evidence.join(required_str(evidence_block, "rpc_receipt_file"));
    let rpc_bytes = fs::read(&rpc_path).expect("read QuickSwap RPC receipt");
    assert_eq!(
        sha256_hex(&rpc_bytes),
        required_str(evidence_block, "rpc_receipt_sha256")
    );
    let rpc: Value = serde_json::from_slice(&rpc_bytes).expect("parse QuickSwap RPC receipt");
    let responses = rpc["responses"]
        .as_array()
        .expect("dual RPC response array");
    assert_eq!(responses.len(), 2);
    for response in responses {
        assert_eq!(response["fixed_block"]["hash"], evidence_block["hash"]);
        assert_eq!(
            response["fixed_block"]["stateRoot"],
            evidence_block["state_root"]
        );
        assert_eq!(response["code"]["bytes"], runtime_spec["bytes"]);
        assert_eq!(response["code"]["sha256"], runtime_spec["sha256"]);
        assert_eq!(response["code"]["keccak256"], runtime_spec["keccak256"]);
        for key in ["eip1967_implementation", "eip1967_admin", "eip1967_beacon"] {
            assert_eq!(
                decode_hex_text(required_str(&response["storage"], key)),
                [0u8; 32]
            );
        }
        assert_eq!(
            decode_abi_word_address(required_str(&response["calls"], "factory")),
            "0x5757371414417b8c6caad45baef941abc7d3ab32"
        );
        assert_eq!(
            decode_abi_word_address(required_str(&response["calls"], "WETH")),
            "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"
        );
        assert_eq!(
            response["deployment_transaction"]["hash"],
            deployment["transaction_hash"]
        );
        assert_eq!(
            response["deployment_receipt"]["contractAddress"],
            deployment["receipt_contract_address"]
        );
        assert_eq!(
            response["deployment_block"]["hash"],
            deployment["block_hash"]
        );
        assert_eq!(
            response["deployment_block"]["stateRoot"],
            deployment["state_root"]
        );
    }

    let source_spec = &manifest["verified_source"];
    assert_eq!(
        source_spec["upstream_commit"].as_str(),
        Some("69617118cda519dab608898d62aaa79877a61004")
    );
    assert_eq!(
        source_spec["upstream_tree"].as_str(),
        Some("c51c6054bdf6ebb391a57212882587e58ae6a374")
    );
    assert_eq!(
        source_spec["sourcify_creation_match"].as_str(),
        Some("match")
    );
    assert_eq!(
        source_spec["sourcify_runtime_match"].as_str(),
        Some("match")
    );
    assert_eq!(
        source_spec["compiler"].as_str(),
        Some("0.6.6+commit.6c089d02")
    );
    assert_eq!(source_spec["evm_version"].as_str(), Some("istanbul"));
    assert_eq!(source_spec["optimizer_runs"].as_u64(), Some(999_999));
    let mut archived = BTreeMap::<String, String>::new();
    for file in source_spec["files"].as_array().expect("source file array") {
        let archive_file = required_str(file, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read QuickSwap source input");
        assert_eq!(bytes.len() as u64, file["bytes"].as_u64().unwrap());
        assert_eq!(sha256_hex(&bytes), required_str(file, "sha256"));
        archived.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("QuickSwap source input is UTF-8"),
        );
    }
    let waffle: Value = serde_json::from_str(&archived["build/.waffle.json"])
        .expect("parse QuickSwap waffle config");
    assert_eq!(
        waffle["compilerOptions"]["evmVersion"].as_str(),
        Some("istanbul")
    );
    assert_eq!(
        waffle["compilerOptions"]["optimizer"]["runs"].as_u64(),
        Some(999_999)
    );
    let package: Value = serde_json::from_str(&archived["build/package.json"])
        .expect("parse QuickSwap package manifest");
    assert_eq!(package["devDependencies"]["solc"].as_str(), Some("0.6.6"));
    assert_eq!(
        package["dependencies"]["@uniswap/v2-core"].as_str(),
        Some("1.0.0")
    );
    assert_eq!(
        package["dependencies"]["@uniswap/lib"].as_str(),
        Some("1.1.1")
    );

    let router = &archived["source/UniswapV2Router02.sol"];
    let remove = normalized_solidity_function(router, "function removeLiquidity(");
    assert_fragments_in_order(
        &remove,
        &[
            "ensure(deadline)",
            "UniswapV2Library.pairFor(factory, tokenA, tokenB)",
            "transferFrom(msg.sender, pair, liquidity)",
            "burn(to)",
            "tokenA == token0 ? (amount0, amount1) : (amount1, amount0)",
            "amountA >= amountAMin",
            "amountB >= amountBMin",
        ],
    );
    let remove_native = normalized_solidity_function(router, "function removeLiquidityETH(");
    assert_fragments_in_order(
        &remove_native,
        &[
            "removeLiquidity(",
            "token, WETH, liquidity, amountTokenMin, amountETHMin, address(this), deadline",
            "safeTransfer(token, to, amountToken)",
            "withdraw(amountETH)",
            "safeTransferETH(to, amountETH)",
        ],
    );
    let supporting = normalized_solidity_function(
        router,
        "function removeLiquidityETHSupportingFeeOnTransferTokens(",
    );
    assert_fragments_in_order(
        &supporting,
        &[
            "removeLiquidity(",
            "token, WETH, liquidity, amountTokenMin, amountETHMin, address(this), deadline",
            "safeTransfer(token, to, IERC20(token).balanceOf(address(this)))",
            "withdraw(amountETH)",
            "safeTransferETH(to, amountETH)",
        ],
    );
    let library = normalized_whitespace(&archived["source/UniswapV2Library.sol"]);
    assert_fragments_in_order(
        &library,
        &[
            "function pairFor(address factory, address tokenA, address tokenB)",
            "sortTokens(tokenA, tokenB)",
            "hex'ff'",
            "factory",
            "keccak256(abi.encodePacked(token0, token1))",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read QuickSwap route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse QuickSwap route ABI");
    let abi_entries = abi.as_array().expect("QuickSwap route ABI array");
    assert_eq!(abi_entries.len(), 3);
    for entry in abi_entries {
        assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
        let types = entry["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| input["type"].as_str().unwrap())
            .collect::<Vec<_>>();
        let signature = format!("{}({})", entry["name"].as_str().unwrap(), types.join(","));
        assert!(
            admitted.contains_key(&signature),
            "unexpected ABI route {signature}"
        );
    }

    let descriptor_spec = &manifest["descriptor"];
    let curated = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated QuickSwap descriptor");
    assert_eq!(
        sha256_hex(&curated),
        required_str(descriptor_spec, "sha256")
    );
    assert_eq!(
        curated,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read installed QuickSwap descriptor")
    );
    let descriptor: Value = serde_json::from_slice(&curated).expect("parse QuickSwap descriptor");
    assert!(descriptor["context"]["contract"]["deployments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|candidate| candidate["chainId"].as_u64() == Some(137)
            && candidate["address"].as_str().is_some_and(
                |address| address.eq_ignore_ascii_case(required_str(deployment, "address"))
            )));
    for route in admitted_specs {
        let fields = descriptor["display"]["formats"][required_str(route, "descriptor_format_key")]
            ["fields"]
            .as_array()
            .expect("QuickSwap descriptor fields");
        assert_eq!(fields[0]["path"].as_str(), Some("liquidity"));
        assert_eq!(fields[0]["label"].as_str(), Some("LP token amount"));
        assert_eq!(fields[0]["format"].as_str(), Some("raw"));
        assert_eq!(fields[0]["visible"].as_str(), Some("always"));
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capabilities");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-QuickSwap.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].chain_id, 137);
    assert_eq!(entries[0].contract, contract);
    let ir = Erc7730Ir::parse(&entries[0].ir_bytes).expect("parse QuickSwap IR");
    let admitted_ir: BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("QuickSwap format parses").selector)
        .collect();
    let expected_ir = BTreeSet::from([
        keccak256(b"addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)")[..4]
            .try_into()
            .unwrap(),
        keccak256(b"addLiquidityETH(address,uint256,uint256,uint256,address,uint256)")[..4]
            .try_into()
            .unwrap(),
        admitted["removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)"],
        admitted["removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)"],
        admitted["removeLiquidityETHSupportingFeeOnTransferTokens(address,uint256,uint256,uint256,address,uint256)"],
    ]);
    assert_eq!(
        admitted_ir, expected_ir,
        "only five static QuickSwap routes are admitted"
    );

    for route in admitted_specs {
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .unwrap();
        let format = ir
            .find_format_by_selector(&selector)
            .expect("QuickSwap format table parses")
            .expect("admitted QuickSwap route exists");
        assert_eq!(
            format.static_head_words as u64,
            route["head_words"].as_u64().unwrap()
        );
        let fields: Vec<_> = format
            .fields()
            .map(|field| field.expect("QuickSwap field parses"))
            .collect();
        assert_eq!(fields.len(), 5);
        let liquidity_word = route["liquidity_word"].as_u64().unwrap() as u8;
        assert_eq!(fields[0].label, b"LP token amount");
        assert_eq!(FormatOp::try_from(fields[0].format_op), Ok(FormatOp::Raw));
        assert_eq!(
            ir.path_bytes(fields[0].path_off).unwrap(),
            [
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                liquidity_word,
            ]
        );
        let liquidity = parse_params(&ir, fields[0].param_off).expect("liquidity params");
        assert_eq!(liquidity.visibility, Visibility::Always);
        assert_eq!(liquidity.terminal_kind, Some(TerminalKind::Unsigned));
        assert_eq!(liquidity.integer_width_bytes, Some(32));
        assert!(liquidity.token.is_none());
        assert!(liquidity.token_path.is_none());
        assert!(registry.known_calls.contains(&(137, contract, selector)));
    }

    for route in manifest["policy"]["excluded_routes"]
        .as_array()
        .expect("excluded route array")
    {
        let signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .expect("excluded selector width");
        assert_eq!(&keccak256(signature.as_bytes())[..4], selector.as_slice());
        assert!(
            ir.find_format_by_selector(&selector)
                .expect("QuickSwap format table parses")
                .is_none(),
            "excluded QuickSwap route entered IR: {signature}"
        );
        assert!(
            registry.known_calls.contains(&(137, contract, selector)),
            "excluded QuickSwap route lost exact known-call refusal: {signature}"
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            137,
            &contract,
            &selector,
        ));
    }
}
