//! Test-only conformance lane for the pinned upstream ERC-7730 positives.
//!
//! The imported fixture bytes live under `tests/erc7730-upstream-fixtures/`,
//! outside every production catalogue input. This test owns two deliberately
//! separate claims:
//!
//! 1. the complete upstream positive corpus is byte-receipted, structurally
//!    valid, mapped to a descriptor, and honestly inventoried; and
//! 2. individually enrolled cases can be decoded and compared against the
//!    actual PQ1 renderer, with exact per-token waivers that must all be used.
//!
//! Positive fixtures are not downgrade-safety evidence. Adversarial negative
//! generation remains a separate open work item.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712, BindingError};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, BundleError};
use pqsigner_erc7730::display::primitives::{amount_is_exact_at_fraction_digits, write_addr_full};
use pqsigner_erc7730::display::render::{render_erc7730_eip712_pages, render_erc7730_pages};
use pqsigner_erc7730::display::DISPLAY_COLS;
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_erc7730::render::params::{parse as parse_params, NFT_COLLECTION_TO_PATH};
use pqsigner_erc7730::render::RenderErr;
use pqsigner_tx::erc20::bundle::{metadata_shape_is_device_verifiable, Erc20Metadata};
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::{self, Eip1559Tx, U256};
use pqsigner_tx_core::hash::keccak256;
use pqsigner_tx_core::rlp::{self, decode_item, Item, ListIter};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sphincs_tz_shared::db_format::ERC20_HDR_OFF_PROOF_DEPTH;

const UPSTREAM_SHA: &str = "784c87c925e8438e7b4736b2af85a501f8d2a265";
const FIXTURE_RECEIPT_DOMAIN: &[u8] = b"pqsigner/erc7730-excluded-fixture-corpus-v1";
const FIXTURE_RECEIPT_HEX: &str =
    "689a0904b10841fbd5d9ead4a6b8e049f04a5146eac88b6d8f2faa565abd685f";
// Router02's two single-hop formats are enrolled only with exact authenticated
// guards for their sentinel and partial-fill semantics. The upstream fixture
// bytes remain test-only and outside the catalogue.
const PROD_ROOT_HEX: &str = "99e4b2556f5a77d6e7d9b8f07b067e9b87a4187b3e472375e602877a2810bcfe";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen sits one level below the workspace root")
        .to_path_buf()
}

fn fixture_root() -> PathBuf {
    workspace_root().join("tests/erc7730-upstream-fixtures")
}

fn prod_registry_root() -> PathBuf {
    workspace_root().join("secure/data/erc7730-registry/registry")
}

fn collect_regular_files(dir: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let metadata = std::fs::symlink_metadata(dir)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", dir.display()));
    assert!(metadata.is_dir(), "not a directory: {}", dir.display());
    assert!(
        !metadata.file_type().is_symlink(),
        "symlinked fixture directory: {}",
        dir.display()
    );

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("read fixture entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().expect("fixture entry type");
        assert!(
            !kind.is_symlink(),
            "symlinked fixture entry: {}",
            path.display()
        );
        if kind.is_dir() {
            collect_regular_files(&path, suffix, out);
        } else if kind.is_file() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("UTF-8 fixture name");
            if name.ends_with(suffix) {
                out.push(path);
            }
        } else {
            panic!("unsupported fixture filesystem entry: {}", path.display());
        }
    }
}

fn fixture_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_regular_files(&fixture_root().join("registry"), ".tests.json", &mut files);
    files.sort();
    files
}

fn fixture_receipt(files: &[PathBuf]) -> ([u8; 32], u64) {
    let root = fixture_root();
    let count = u64::try_from(files.len()).expect("fixture count fits u64");
    let mut aggregate = Sha256::new();
    aggregate.update(FIXTURE_RECEIPT_DOMAIN);
    aggregate.update(count.to_be_bytes());
    let mut total_bytes = 0u64;
    for path in files {
        let relative = path.strip_prefix(&root).expect("fixture beneath root");
        let relative = relative.to_str().expect("UTF-8 fixture path");
        let bytes = std::fs::read(path).expect("read fixture bytes");
        let path_len = u32::try_from(relative.len()).expect("fixture path fits u32");
        let file_len = u64::try_from(bytes.len()).expect("fixture size fits u64");
        total_bytes = total_bytes
            .checked_add(file_len)
            .expect("fixture byte sum fits u64");
        aggregate.update(path_len.to_be_bytes());
        aggregate.update(relative.as_bytes());
        aggregate.update(file_len.to_be_bytes());
        aggregate.update(Sha256::digest(&bytes));
    }
    let mut receipt = [0u8; 32];
    receipt.copy_from_slice(&aggregate.finalize());
    (receipt, total_bytes)
}

#[derive(Default, Debug)]
struct FixtureStats {
    files: usize,
    entities: BTreeSet<String>,
    calldata_files: usize,
    eip712_files: usize,
    cases: usize,
    calldata_cases: usize,
    eip712_cases: usize,
    tx_hash_cases: usize,
    expected_strings: usize,
    empty_expected_cases: usize,
    odd_expected_cases: usize,
    interaction_with: usize,
    max_fees: usize,
    address_like_wrapped: usize,
    numeric_wrapped: usize,
    unresolved_ticker: usize,
    truncated_more: usize,
    over_pq1_page: usize,
    type2_cases: usize,
    type2_unsigned: usize,
    type2_signed: usize,
    legacy_cases: usize,
    non_envelope_payload_cases: usize,
}

fn is_wrapped_address(text: &str) -> bool {
    text.starts_with("0x")
        && text.contains(' ')
        && text
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_hexdigit() || byte == b'x')
}

fn has_digit_space_digit(text: &str) -> bool {
    text.as_bytes()
        .windows(3)
        .any(|window| window[0].is_ascii_digit() && window[1] == b' ' && window[2].is_ascii_digit())
}

fn rlp_field_count(raw: &[u8], typed: bool) -> Option<usize> {
    let payload = if typed { &raw[1..] } else { raw };
    let (item, used) = decode_item(payload).ok()?;
    if used != payload.len() {
        return None;
    }
    let Item::List(list) = item else {
        return None;
    };
    let mut iter = ListIter::new(list);
    let mut count = 0usize;
    while iter
        .next_item()
        .expect("fixture transaction field RLP")
        .is_some()
    {
        count += 1;
    }
    Some(count)
}

fn descriptor_relative_path(fixture: &Path) -> PathBuf {
    let relative = fixture
        .strip_prefix(fixture_root().join("registry"))
        .expect("fixture below registry root");
    let mut components: Vec<_> = relative.components().collect();
    assert!(
        components.len() >= 3,
        "unexpected fixture path: {}",
        relative.display()
    );
    assert_eq!(components[components.len() - 2].as_os_str(), "tests");
    components.remove(components.len() - 2);
    let mut descriptor = PathBuf::new();
    for component in components {
        descriptor.push(component.as_os_str());
    }
    let name = descriptor
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 descriptor name");
    assert!(name.ends_with(".tests.json"));
    descriptor.set_file_name(name.replace(".tests.json", ".json"));
    descriptor
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FormatId {
    Calldata([u8; 4]),
    Eip712([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FormatKey {
    source: PathBuf,
    id: FormatId,
}

fn eip712_struct_definition(name: &str, definitions: &serde_json::Map<String, Value>) -> String {
    let members = definitions
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("EIP-712 type `{name}` has no member array"));
    let mut definition = String::with_capacity(name.len() + 2 + members.len() * 16);
    definition.push_str(name);
    definition.push('(');
    for (index, member) in members.iter().enumerate() {
        let member = member.as_object().expect("EIP-712 member object");
        if index != 0 {
            definition.push(',');
        }
        definition.push_str(
            member
                .get("type")
                .and_then(Value::as_str)
                .expect("EIP-712 member type"),
        );
        definition.push(' ');
        definition.push_str(
            member
                .get("name")
                .and_then(Value::as_str)
                .expect("EIP-712 member name"),
        );
    }
    definition.push(')');
    definition
}

fn eip712_base_type(ty: &str) -> &str {
    ty.split_once('[').map_or(ty, |(base, _)| base)
}

fn collect_eip712_dependencies(
    name: &str,
    definitions: &serde_json::Map<String, Value>,
    dependencies: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
) {
    assert!(
        active.insert(name.to_string()),
        "cyclic EIP-712 fixture type: {name}"
    );
    let members = definitions
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("EIP-712 type `{name}` has no member array"));
    for member in members {
        let ty = member
            .get("type")
            .and_then(Value::as_str)
            .expect("EIP-712 member type");
        let base = eip712_base_type(ty);
        if definitions.contains_key(base) && dependencies.insert(base.to_string()) {
            collect_eip712_dependencies(base, definitions, dependencies, active);
        }
    }
    active.remove(name);
}

fn fixture_primary_type_hash(data: &serde_json::Map<String, Value>) -> [u8; 32] {
    let primary_type = data
        .get("primaryType")
        .and_then(Value::as_str)
        .expect("EIP-712 primaryType");
    let definitions = data
        .get("types")
        .and_then(Value::as_object)
        .expect("EIP-712 types object");
    let mut dependencies = BTreeSet::new();
    collect_eip712_dependencies(
        primary_type,
        definitions,
        &mut dependencies,
        &mut BTreeSet::new(),
    );
    dependencies.remove(primary_type);
    dependencies.remove("EIP712Domain");

    let mut encode_type = eip712_struct_definition(primary_type, definitions);
    for dependency in dependencies {
        encode_type.push_str(&eip712_struct_definition(&dependency, definitions));
    }
    keccak256(encode_type.as_bytes())
}

fn parse_fixture_address(value: &Value) -> [u8; 20] {
    let text = value.as_str().expect("fixture address string");
    let bytes = hex::decode(text.strip_prefix("0x").expect("fixture address 0x prefix"))
        .expect("fixture address hex");
    bytes.try_into().expect("fixture address is 20 bytes")
}

fn fixture_u256_word(value: &Value) -> [u8; 32] {
    let decimal = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => panic!("fixture uint256 number or string"),
    };
    assert!(!decimal.is_empty(), "fixture uint256 is empty");
    assert!(
        decimal.bytes().all(|byte| byte.is_ascii_digit()),
        "fixture uint256 is not unsigned decimal"
    );
    assert!(
        decimal == "0" || !decimal.starts_with('0'),
        "fixture uint256 has a leading zero"
    );

    let mut word = [0u8; 32];
    for digit in decimal.bytes() {
        let mut carry = u16::from(digit - b'0');
        for byte in word.iter_mut().rev() {
            let product = u16::from(*byte) * 10 + carry;
            *byte = product as u8;
            carry = product >> 8;
        }
        assert_eq!(carry, 0, "fixture uint256 exceeds 256 bits");
    }
    word
}

fn fixture_static_word(ty: &str, value: &Value) -> [u8; 32] {
    match ty {
        "address" => {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&parse_fixture_address(value));
            word
        }
        "bool" => {
            let mut word = [0u8; 32];
            word[31] = u8::from(value.as_bool().expect("fixture bool"));
            word
        }
        "bytes32" => {
            let text = value.as_str().expect("fixture bytes32 string");
            let bytes = hex::decode(text.strip_prefix("0x").expect("fixture bytes32 0x prefix"))
                .expect("fixture bytes32 hex");
            bytes.try_into().expect("fixture bytes32 width")
        }
        _ if ty.starts_with("uint") => {
            let suffix = &ty[4..];
            let bits = if suffix.is_empty() {
                256
            } else {
                suffix.parse::<usize>().expect("fixture uint width")
            };
            assert!(
                (8..=256).contains(&bits) && bits % 8 == 0,
                "fixture uint width is invalid"
            );
            let word = fixture_u256_word(value);
            let width = bits / 8;
            assert!(
                word[..32 - width].iter().all(|byte| *byte == 0),
                "fixture value does not fit {ty}"
            );
            word
        }
        _ => panic!("unsupported flat-static fixture member type `{ty}`"),
    }
}

struct FlatStaticEip712 {
    chain_id: u64,
    verifying_contract: [u8; 20],
    domain_separator: [u8; 32],
    primary_type_hash: [u8; 32],
    encoded_data: Vec<u8>,
}

fn encode_flat_static_eip712(data: &serde_json::Map<String, Value>) -> FlatStaticEip712 {
    let definitions = data["types"].as_object().expect("EIP-712 types object");
    let domain = data["domain"].as_object().expect("EIP-712 domain object");
    let domain_members = definitions["EIP712Domain"]
        .as_array()
        .expect("EIP712Domain members");
    let chain_id = domain["chainId"].as_u64().expect("fixture domain chainId");
    let verifying_contract = parse_fixture_address(&domain["verifyingContract"]);
    let mut domain_preimage = Vec::with_capacity((domain_members.len() + 1) * 32);
    domain_preimage.extend_from_slice(&keccak256(
        eip712_struct_definition("EIP712Domain", definitions).as_bytes(),
    ));
    let mut seen_domain_members = BTreeSet::new();
    for member in domain_members {
        let name = member["name"].as_str().expect("domain member name");
        let ty = member["type"].as_str().expect("domain member type");
        assert!(
            seen_domain_members.insert(name),
            "duplicate fixture domain member"
        );
        match (name, ty) {
            ("name" | "version", "string") => domain_preimage.extend_from_slice(&keccak256(
                domain[name]
                    .as_str()
                    .unwrap_or_else(|| panic!("fixture domain {name}"))
                    .as_bytes(),
            )),
            ("chainId", "uint256") | ("verifyingContract", "address") => {
                domain_preimage.extend_from_slice(&fixture_static_word(ty, &domain[name]));
            }
            _ => panic!("unsupported flat-static fixture domain member `{ty} {name}`"),
        }
    }
    assert!(seen_domain_members.contains("name"));
    assert!(seen_domain_members.contains("chainId"));
    assert!(seen_domain_members.contains("verifyingContract"));

    let primary_type = data["primaryType"].as_str().expect("fixture primaryType");
    let message = data["message"].as_object().expect("fixture message object");
    let members = definitions[primary_type]
        .as_array()
        .expect("fixture primary type members");
    let mut encoded_data = Vec::with_capacity(members.len() * 32);
    for member in members {
        let name = member["name"].as_str().expect("message member name");
        let ty = member["type"].as_str().expect("message member type");
        encoded_data.extend_from_slice(&fixture_static_word(ty, &message[name]));
    }

    FlatStaticEip712 {
        chain_id,
        verifying_contract,
        domain_separator: keccak256(&domain_preimage),
        primary_type_hash: fixture_primary_type_hash(data),
        encoded_data,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureShellKind {
    Type2,
    LegacyOrBare,
}

fn classify_fixture_shell(raw: &[u8]) -> Result<FixtureShellKind, u8> {
    let first = *raw.first().expect("empty fixture rawTx");
    match first {
        0x02 => Ok(FixtureShellKind::Type2),
        unsupported @ 0x00..=0x7f => Err(unsupported),
        _ => Ok(FixtureShellKind::LegacyOrBare),
    }
}

fn supported_fixture_shell(raw: &[u8]) -> FixtureShellKind {
    classify_fixture_shell(raw).unwrap_or_else(|unsupported| {
        panic!("unsupported EIP-2718 fixture envelope type 0x{unsupported:02x}")
    })
}

fn fixture_calldata(raw: &[u8]) -> &[u8] {
    let (typed, payload, data_index) = match supported_fixture_shell(raw) {
        FixtureShellKind::Type2 => (true, &raw[1..], 7usize),
        FixtureShellKind::LegacyOrBare => (false, raw, 5usize),
    };
    let Ok((Item::List(list), used)) = decode_item(payload) else {
        assert!(!typed, "typed fixture must contain an RLP list");
        return raw;
    };
    if used != payload.len() {
        assert!(!typed, "typed fixture has trailing envelope bytes");
        return raw;
    }
    let mut iter = ListIter::new(list);
    for index in 0..=data_index {
        let item = iter
            .next_item()
            .expect("fixture transaction field RLP")
            .expect("fixture transaction field");
        if index == data_index {
            return match item {
                Item::Bytes(bytes) => bytes,
                Item::List(_) => panic!("fixture calldata is an RLP list"),
            };
        }
    }
    unreachable!()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureEnvelopeKind {
    SignedType2,
    LegacyEip155Preimage,
}

struct AdaptedFixtureTx {
    kind: FixtureEnvelopeKind,
    tx: Eip1559Tx,
    data: Vec<u8>,
}

fn push_rlp_list_prefix(payload_len: usize, out: &mut Vec<u8>) {
    if payload_len <= 55 {
        out.push(0xc0 + u8::try_from(payload_len).expect("short RLP list length"));
        return;
    }
    let bytes = payload_len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("nonzero long RLP list length");
    let length_bytes = &bytes[first..];
    out.push(0xf7 + u8::try_from(length_bytes.len()).expect("RLP length-of-length"));
    out.extend_from_slice(length_bytes);
}

// Test-only envelope normalization: authenticate no signature and grant no
// production signing authority; retain the nine signed transaction fields and
// pass their canonical unsigned Type-2 form through the production parser.
fn adapt_signed_type2_fixture(raw: &[u8]) -> AdaptedFixtureTx {
    assert_eq!(
        supported_fixture_shell(raw),
        FixtureShellKind::Type2,
        "fixture is not Type-2"
    );
    let (Item::List(list), used) = decode_item(&raw[1..]).expect("signed Type-2 outer RLP") else {
        panic!("signed Type-2 outer item is not a list");
    };
    assert_eq!(used, raw.len() - 1, "signed Type-2 trailing bytes");

    let mut raw_fields = Vec::new();
    let mut decoded_fields = Vec::new();
    let mut cursor = 0usize;
    while cursor < list.len() {
        let (item, field_len) = decode_item(&list[cursor..]).expect("signed Type-2 field RLP");
        raw_fields.push(&list[cursor..cursor + field_len]);
        decoded_fields.push(item);
        cursor += field_len;
    }
    assert_eq!(decoded_fields.len(), 12, "expected signed Type-2 fixture");
    let Item::Bytes(y_parity) = decoded_fields[9] else {
        panic!("Type-2 yParity is not bytes");
    };
    assert!(rlp::bytes_to_u64(y_parity).expect("canonical yParity") <= 1);
    for (name, field) in [("r", decoded_fields[10]), ("s", decoded_fields[11])] {
        let Item::Bytes(bytes) = field else {
            panic!("Type-2 {name} is not bytes");
        };
        let value = rlp::bytes_to_u256(bytes).unwrap_or_else(|_| panic!("canonical Type-2 {name}"));
        assert!(
            value.iter().any(|byte| *byte != 0),
            "signed Type-2 {name} is zero"
        );
    }

    let unsigned_payload_len: usize = raw_fields[..9].iter().map(|field| field.len()).sum();
    let mut unsigned = Vec::with_capacity(1 + 9 + unsigned_payload_len);
    unsigned.push(0x02);
    push_rlp_list_prefix(unsigned_payload_len, &mut unsigned);
    for field in &raw_fields[..9] {
        unsigned.extend_from_slice(field);
    }
    let parsed =
        eip1559::parse(&unsigned).expect("adapted unsigned Type-2 passes production parser");
    AdaptedFixtureTx {
        kind: FixtureEnvelopeKind::SignedType2,
        data: parsed.data.to_vec(),
        tx: parsed.tx,
    }
}

// Test-only display shim for canonical unsigned EIP-155 preimages. Production
// legacy parsing/signing stays unsupported; gas-price mapping exists only so
// the real descriptor renderer can consume an `Eip1559Tx`-shaped fixture.
fn adapt_legacy_eip155_fixture(raw: &[u8]) -> AdaptedFixtureTx {
    assert_eq!(
        supported_fixture_shell(raw),
        FixtureShellKind::LegacyOrBare,
        "fixture is not legacy"
    );
    let (Item::List(list), used) = decode_item(raw).expect("legacy fixture outer RLP") else {
        panic!("legacy fixture outer item is not a list");
    };
    assert_eq!(used, raw.len(), "legacy fixture trailing bytes");
    let mut fields = ListIter::new(list);
    let nonce = rlp::bytes_to_u64(fields.expect_bytes().expect("legacy nonce"))
        .expect("canonical legacy nonce");
    let gas_price = U256(
        rlp::bytes_to_u256(fields.expect_bytes().expect("legacy gas price"))
            .expect("canonical legacy gas price"),
    );
    let gas_limit = rlp::bytes_to_u64(fields.expect_bytes().expect("legacy gas limit"))
        .expect("canonical legacy gas limit");
    let to_bytes = fields.expect_bytes().expect("legacy to");
    let to: [u8; 20] = to_bytes.try_into().expect("legacy target is 20 bytes");
    let value = U256(
        rlp::bytes_to_u256(fields.expect_bytes().expect("legacy value"))
            .expect("canonical legacy value"),
    );
    let data = fields.expect_bytes().expect("legacy calldata").to_vec();
    let chain_id = rlp::bytes_to_u64(fields.expect_bytes().expect("legacy EIP-155 chain field"))
        .expect("canonical legacy EIP-155 chain field");
    assert_ne!(chain_id, 0, "legacy EIP-155 chain ID is zero");
    assert!(
        fields
            .expect_bytes()
            .expect("legacy EIP-155 empty r")
            .is_empty(),
        "bounded legacy adapter accepts only unsigned EIP-155 preimages"
    );
    assert!(
        fields
            .expect_bytes()
            .expect("legacy EIP-155 empty s")
            .is_empty(),
        "bounded legacy adapter accepts only unsigned EIP-155 preimages"
    );
    assert!(
        fields.next_item().expect("legacy field RLP").is_none(),
        "legacy fixture has more than nine fields"
    );
    assert!(
        gas_limit >= eip1559::MIN_INTRINSIC_GAS,
        "legacy fixture is below the intrinsic gas floor"
    );

    AdaptedFixtureTx {
        kind: FixtureEnvelopeKind::LegacyEip155Preimage,
        tx: Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: gas_price,
            gas_limit,
            to: Some(to),
            value,
            data_len: data.len(),
            access_list_count: 0,
            signing_hash: keccak256(raw),
            userop_fields: None,
        },
        data,
    }
}

fn fixture_format_keys() -> BTreeSet<FormatKey> {
    let mut keys = BTreeSet::new();
    for fixture in fixture_files() {
        let descriptor = descriptor_relative_path(&fixture);
        let root: Value = serde_json::from_slice(
            &std::fs::read(&fixture).expect("read upstream fixture for format inventory"),
        )
        .expect("parse upstream fixture for format inventory");
        for case in root["tests"].as_array().expect("fixture tests array") {
            let id = if let Some(raw_tx) = case.get("rawTx") {
                let raw_tx = raw_tx.as_str().expect("rawTx string");
                let raw =
                    hex::decode(raw_tx.strip_prefix("0x").expect("0x rawTx")).expect("rawTx hex");
                let calldata = fixture_calldata(&raw);
                assert!(
                    calldata.len() >= 4,
                    "fixture has no calldata selector: {}",
                    fixture.display()
                );
                FormatId::Calldata(calldata[..4].try_into().expect("four-byte selector"))
            } else {
                let data = case["data"].as_object().expect("EIP-712 data object");
                FormatId::Eip712(fixture_primary_type_hash(data))
            };
            keys.insert(FormatKey {
                source: descriptor.clone(),
                id,
            });
        }
    }
    keys
}

fn accepted_format_keys(registry: &dbgen::erc7730::Erc7730BuildResult) -> BTreeSet<FormatKey> {
    let mut keys = BTreeSet::new();
    for entry in &registry.entries {
        let source = entry
            .source
            .strip_prefix(prod_registry_root())
            .unwrap_or_else(|_| panic!("accepted source outside production registry"))
            .to_path_buf();
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("accepted IR parses");
        for format in ir.format_iter() {
            let format = format.expect("accepted format parses");
            let id = match ir.context_kind {
                ContextKind::Contract => FormatId::Calldata(format.selector),
                ContextKind::Eip712 => FormatId::Eip712(format.type_hash),
            };
            keys.insert(FormatKey {
                source: source.clone(),
                id,
            });
        }
    }
    keys
}

fn inventory_fixture(path: &Path, stats: &mut FixtureStats, tested: &mut BTreeSet<PathBuf>) {
    let bytes = std::fs::read(path).expect("read upstream fixture");
    let root: Value = serde_json::from_slice(&bytes).expect("parse upstream fixture JSON");
    let object = root.as_object().expect("fixture root object");
    assert_eq!(
        object.get("$schema").and_then(Value::as_str),
        Some("../../../specs/erc7730-tests.schema.json"),
        "unexpected fixture schema in {}",
        path.display()
    );
    let tests = object
        .get("tests")
        .and_then(Value::as_array)
        .expect("fixture tests array");
    assert!(
        !tests.is_empty(),
        "fixture file has no cases: {}",
        path.display()
    );

    let descriptor = descriptor_relative_path(path);
    assert!(
        prod_registry_root().join(&descriptor).is_file(),
        "orphan fixture has no sibling descriptor: {} -> {}",
        path.display(),
        descriptor.display()
    );
    tested.insert(descriptor.clone());
    stats.entities.insert(
        descriptor
            .components()
            .next()
            .expect("fixture entity")
            .as_os_str()
            .to_str()
            .expect("UTF-8 entity")
            .to_string(),
    );

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 fixture file");
    let file_is_calldata = file_name.starts_with("calldata-");
    let file_is_eip712 = file_name.starts_with("eip712-");
    assert_ne!(
        file_is_calldata, file_is_eip712,
        "mixed/unknown fixture filename: {file_name}"
    );
    if file_is_calldata {
        stats.calldata_files += 1;
    } else {
        stats.eip712_files += 1;
    }

    stats.files += 1;
    for case in tests {
        let case = case.as_object().expect("fixture case object");
        assert!(
            case.get("description")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty()),
            "fixture case lacks a description in {}",
            path.display()
        );
        let raw_tx = case.get("rawTx");
        let data = case.get("data");
        assert_ne!(
            raw_tx.is_some(),
            data.is_some(),
            "case must be exactly calldata or EIP-712"
        );
        assert_eq!(
            raw_tx.is_some(),
            file_is_calldata,
            "fixture filename/case-kind mismatch"
        );

        stats.cases += 1;
        if let Some(raw_tx) = raw_tx {
            stats.calldata_cases += 1;
            let raw_tx = raw_tx.as_str().expect("rawTx string");
            assert!(raw_tx.starts_with("0x"), "rawTx lacks 0x prefix");
            let raw = hex::decode(&raw_tx[2..]).expect("rawTx hex");
            assert!(!raw.is_empty(), "empty rawTx");
            match supported_fixture_shell(&raw) {
                FixtureShellKind::Type2 => {
                    stats.type2_cases += 1;
                    match rlp_field_count(&raw, true).expect("type-2 fixture outer RLP") {
                        9 => stats.type2_unsigned += 1,
                        12 => stats.type2_signed += 1,
                        count => panic!(
                            "unexpected EIP-1559 field count {count} in {}",
                            path.display()
                        ),
                    }
                }
                FixtureShellKind::LegacyOrBare => {
                    stats.legacy_cases += 1;
                    match rlp_field_count(&raw, false) {
                        Some(count) => assert!(
                            count >= 6,
                            "legacy fixture has fewer than six transaction fields"
                        ),
                        None => stats.non_envelope_payload_cases += 1,
                    }
                }
            }
            if let Some(tx_hash) = case.get("txHash") {
                let tx_hash = tx_hash.as_str().expect("txHash string");
                assert_eq!(tx_hash.len(), 66, "txHash width");
                assert!(tx_hash.starts_with("0x"));
                hex::decode(&tx_hash[2..]).expect("txHash hex");
                stats.tx_hash_cases += 1;
            }
        } else {
            stats.eip712_cases += 1;
            let data = data
                .and_then(Value::as_object)
                .expect("EIP-712 data object");
            for key in ["types", "primaryType", "domain", "message"] {
                assert!(data.contains_key(key), "EIP-712 fixture lacks `{key}`");
            }
        }

        let expected = case
            .get("expectedTexts")
            .and_then(Value::as_array)
            .expect("every imported case must carry expectedTexts");
        if expected.is_empty() {
            stats.empty_expected_cases += 1;
        }
        if expected.len() % 2 == 1 {
            stats.odd_expected_cases += 1;
        }
        stats.expected_strings += expected.len();
        for text in expected {
            let text = text.as_str().expect("expectedTexts string");
            assert!(
                text.is_ascii(),
                "non-ASCII expected text in {}",
                path.display()
            );
            assert_eq!(text.trim(), text, "expected text has edge whitespace");
            assert!(
                !text.contains(['\n', '\r', '\t']),
                "expected text has control whitespace"
            );
            assert!(!text.contains("  "), "expected text has repeated spaces");
            stats.interaction_with += usize::from(text == "Interaction with");
            stats.max_fees += usize::from(text == "Max fees");
            stats.address_like_wrapped += usize::from(is_wrapped_address(text));
            stats.numeric_wrapped += usize::from(has_digit_space_digit(text));
            stats.unresolved_ticker += usize::from(text.contains("???"));
            stats.truncated_more += usize::from(text.ends_with("... More"));
            stats.over_pq1_page += usize::from(text.len() > 64);
        }
    }
}

fn build_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static REGISTRY: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let root = workspace_root();
        let registry = root.join("secure/data/erc7730-registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
            .expect("build exact production ERC20 capability corpus");
        let (result, _) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &registry.join("registry"),
            &policy,
            Some(&registry),
            &erc20.capabilities,
        )
        .expect("build production registry for conformance test");
        result
    })
}

#[test]
fn upstream_fixture_targets_are_inventoried_at_format_granularity() {
    let fixture_targets = fixture_format_keys();
    let accepted = accepted_format_keys(build_registry());
    let fixture_and_accepted: BTreeSet<_> = fixture_targets.intersection(&accepted).collect();
    let accepted_without_fixture: BTreeSet<_> = accepted.difference(&fixture_targets).collect();
    let fixture_without_accepted_format: BTreeSet<_> =
        fixture_targets.difference(&accepted).collect();

    for selector in [[0x04, 0xe4, 0x5a, 0xaf], [0x50, 0x23, 0xb4, 0xdf]] {
        let router02_single_hop = FormatKey {
            source: PathBuf::from("uniswap/calldata-UniswapV3Router02.json"),
            id: FormatId::Calldata(selector),
        };
        assert!(
            fixture_targets.contains(&router02_single_hop),
            "Router02 single-hop selector is absent from the pinned upstream fixtures"
        );
        assert!(
            accepted.contains(&router02_single_hop),
            "Router02 single-hop selector is absent from the production catalogue"
        );
    }

    let policy: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("projection-policy.json"))
            .expect("read projection policy"),
    )
    .expect("parse projection policy");
    let coverage = policy["format_coverage"]
        .as_object()
        .expect("format coverage receipt");
    for (name, actual) in [
        ("fixture_targets", fixture_targets.len()),
        ("accepted_formats", accepted.len()),
        ("fixture_targets_accepted", fixture_and_accepted.len()),
        ("accepted_without_fixture", accepted_without_fixture.len()),
        (
            "fixture_without_accepted_format",
            fixture_without_accepted_format.len(),
        ),
    ] {
        assert_eq!(
            coverage[name].as_u64(),
            Some(u64::try_from(actual).expect("format coverage count fits u64")),
            "stale format-level fixture coverage receipt: {name}"
        );
    }
}

fn fixture_case(relative: &str, case_index: usize) -> (Value, Vec<u8>) {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join(relative)).expect("read fixture case"),
    )
    .expect("parse fixture case");
    let raw_hex = fixture["tests"][case_index]["rawTx"]
        .as_str()
        .expect("fixture rawTx");
    let raw =
        hex::decode(raw_hex.strip_prefix("0x").expect("0x rawTx")).expect("fixture rawTx hex");
    (fixture, raw)
}

#[test]
fn unsupported_typed_fixture_envelopes_refuse_before_projection() {
    let (_, type2_raw) = fixture_case(
        "registry/threshold/tests/calldata-RebateStaking.tests.json",
        0,
    );
    assert_eq!(
        classify_fixture_shell(&type2_raw),
        Ok(FixtureShellKind::Type2)
    );
    for unsupported in 0x00u8..=0x7f {
        if unsupported == 0x02 {
            continue;
        }
        let mut mutated = type2_raw.clone();
        mutated[0] = unsupported;
        assert_eq!(
            classify_fixture_shell(&mutated),
            Err(unsupported),
            "typed envelope 0x{unsupported:02x} reached fixture projection"
        );
    }

    let mut type1 = type2_raw;
    type1[0] = 0x01;
    assert!(
        std::panic::catch_unwind(|| fixture_calldata(&type1)).is_err(),
        "the selector-projection path must use the typed-envelope guard"
    );

    let (_, bare) = fixture_case(
        "registry/kyberswap/tests/calldata-MetaAggregationRouterV2.tests.json",
        0,
    );
    assert_eq!(&bare[..4], &[0xe2, 0x1f, 0xd0, 0xe9]);
    assert_eq!(
        classify_fixture_shell(&bare),
        Ok(FixtureShellKind::LegacyOrBare)
    );
    assert_eq!(fixture_calldata(&bare), bare.as_slice());
}

#[test]
fn fixture_transaction_adapters_preserve_signed_payload() {
    let (_, signed_raw) = fixture_case(
        "registry/threshold/tests/calldata-RebateStaking.tests.json",
        0,
    );
    let signed = adapt_signed_type2_fixture(&signed_raw);
    assert_eq!(signed.kind, FixtureEnvelopeKind::SignedType2);
    assert_eq!(signed.tx.chain_id, 1);
    assert_eq!(signed.tx.nonce, 0x50);
    assert_eq!(signed.tx.gas_limit, 0x03d090);
    assert_eq!(
        signed.tx.to,
        Some(
            hex::decode("0184739c32edc3471d3e4860c8e39a5f3ff85a45")
                .expect("target hex")
                .try_into()
                .expect("target address")
        )
    );
    assert_eq!(signed.data.as_slice(), fixture_calldata(&signed_raw));
    assert_eq!(&signed.data[..4], &[0x61, 0xf1, 0x29, 0xad]);
    assert_eq!(
        hex::encode(&signed.data[4..]),
        "00000000000000000000000000000000000000000000003635c9adc5dea00000"
    );

    let (_, legacy_raw) = fixture_case("registry/lido/tests/calldata-wstETH.tests.json", 3);
    let legacy = adapt_legacy_eip155_fixture(&legacy_raw);
    assert_eq!(legacy.kind, FixtureEnvelopeKind::LegacyEip155Preimage);
    assert_eq!(legacy.tx.chain_id, 1);
    assert_eq!(legacy.tx.nonce, 3);
    assert_eq!(legacy.tx.gas_limit, 0x013880);
    assert_eq!(
        legacy.tx.to,
        Some(
            hex::decode("7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0")
                .expect("target hex")
                .try_into()
                .expect("target address")
        )
    );
    assert_eq!(legacy.data.as_slice(), fixture_calldata(&legacy_raw));
    assert_eq!(&legacy.data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    assert_eq!(
        hex::encode(&legacy.data[4..36]),
        "000000000000000000000000db34fbb4e7989c3f8957e9e9b346bf46ee0f0408"
    );
    assert_eq!(
        hex::encode(&legacy.data[36..68]),
        "000000000000000000000000000000000000000000000000000009184e72a000"
    );
}

#[test]
fn production_interpolation_tags_have_exact_static_erc20_capabilities() {
    let root = workspace_root();
    let erc20_path = root.join("secure/data/erc20.json");
    let erc20 = dbgen::erc20::build_db(&erc20_path)
        .expect("build exact production ERC20 capability corpus");
    let metadata: BTreeMap<_, _> = dbgen::load_erc20_records(&erc20_path)
        .expect("load production ERC20 metadata")
        .into_iter()
        .map(|record| {
            let contract =
                dbgen::parse_hex_address(&record.address).expect("production ERC20 address parses");
            ((record.chain_id, contract), record)
        })
        .collect();
    let proof_depth = u32::from_le_bytes(
        erc20.blob[ERC20_HDR_OFF_PROOF_DEPTH..ERC20_HDR_OFF_PROOF_DEPTH + 4]
            .try_into()
            .expect("ERC20 proof-depth header"),
    ) as usize;
    let registry = build_registry();
    let mut enrolled = 0usize;

    for entry in &registry.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated IR parses");
        for format in ir.format_iter() {
            let format = format.expect("generated format parses");
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("generated field parses"))
                .collect();
            let Some(program) = fields.iter().find_map(|field| {
                parse_params(&ir, field.param_off)
                    .expect("generated params parse")
                    .interpolated_intent
            }) else {
                continue;
            };
            enrolled += 1;
            let ordinal = usize::from(program.field_ordinal(0).expect("enrolled field ordinal"));
            let target = fields
                .get(ordinal)
                .expect("interpolation target field exists");
            let params = parse_params(&ir, target.param_off).expect("target params parse");
            let token = if let Some(path) = params.token_path {
                assert_eq!(
                    path,
                    NFT_COLLECTION_TO_PATH.as_slice(),
                    "an enrolled tokenPath must be deployment-static @.to"
                );
                entry.contract
            } else {
                *params
                    .token
                    .expect("enrolled tokenAmount must carry a static token identity")
            };
            let token_metadata = metadata
                .get(&(entry.chain_id, token))
                .expect("enrolled token has production ERC20 metadata");
            assert!(
                metadata_shape_is_device_verifiable(
                    token_metadata.decimals,
                    token_metadata.name.as_bytes(),
                    token_metadata.symbol.as_bytes(),
                    proof_depth,
                ),
                "interpolation metadata cannot pass the production device verifier"
            );
            assert!(
                erc20.capabilities.contains(entry.chain_id, &token),
                "interpolation lacks exact (chain, token) ERC20 metadata capability"
            );
        }
    }
    assert_eq!(enrolled, 6, "current corpus enrollment changed");
}

#[test]
fn upstream_fixture_corpus_is_exact_test_only_and_honestly_inventoried() {
    let fixtures = fixture_files();
    let (receipt, fixture_bytes) = fixture_receipt(&fixtures);
    assert_eq!(hex::encode(receipt), FIXTURE_RECEIPT_HEX);
    assert_eq!(fixture_bytes, 687_949);

    let fixture_canonical = std::fs::canonicalize(fixture_root()).expect("canonical fixture root");
    let prod_canonical = std::fs::canonicalize(prod_registry_root()).expect("canonical prod root");
    assert!(!fixture_canonical.starts_with(&prod_canonical));
    assert!(!prod_canonical.starts_with(&fixture_canonical));

    let mut stats = FixtureStats::default();
    let mut tested_descriptors = BTreeSet::new();
    for fixture in &fixtures {
        inventory_fixture(fixture, &mut stats, &mut tested_descriptors);
    }

    assert_eq!(stats.files, 272);
    assert_eq!(stats.entities.len(), 42);
    assert_eq!((stats.calldata_files, stats.eip712_files), (154, 118));
    assert_eq!(stats.cases, 510);
    assert_eq!((stats.calldata_cases, stats.eip712_cases), (362, 148));
    assert_eq!(stats.tx_hash_cases, 311);
    assert_eq!(stats.expected_strings, 3_976);
    assert_eq!(stats.empty_expected_cases, 3);
    assert_eq!(stats.odd_expected_cases, 58);
    assert_eq!(stats.interaction_with, 280);
    assert_eq!(stats.max_fees, 275);
    assert_eq!(stats.address_like_wrapped, 400);
    assert_eq!(stats.numeric_wrapped, 608);
    assert_eq!(stats.unresolved_ticker, 28);
    assert_eq!(stats.truncated_more, 6);
    assert_eq!(stats.over_pq1_page, 75);
    assert_eq!(stats.type2_cases, 316);
    assert_eq!((stats.type2_unsigned, stats.type2_signed), (227, 89));
    assert_eq!(stats.legacy_cases, 46);
    assert_eq!(stats.non_envelope_payload_cases, 1);

    let policy: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("projection-policy.json"))
            .expect("read projection policy"),
    )
    .expect("parse projection policy");
    assert_eq!(
        policy.get("upstream_sha").and_then(Value::as_str),
        Some(UPSTREAM_SHA)
    );
    assert_eq!(
        policy.get("fixture_receipt_sha256").and_then(Value::as_str),
        Some(FIXTURE_RECEIPT_HEX)
    );

    let registry = build_registry();
    assert_eq!(
        hex::encode(registry.root),
        PROD_ROOT_HEX,
        "test-only fixtures changed the production root"
    );
    let accepted: BTreeSet<PathBuf> = registry
        .entries
        .iter()
        .map(|entry| {
            entry
                .source
                .strip_prefix(prod_registry_root())
                .unwrap_or_else(|_| {
                    panic!(
                        "entry source outside production registry: {}",
                        entry.source.display()
                    )
                })
                .to_path_buf()
        })
        .collect();
    assert_eq!(accepted.len(), 232);
    assert_eq!(accepted.intersection(&tested_descriptors).count(), 147);
    assert_eq!(accepted.difference(&tested_descriptors).count(), 85);
    assert_eq!(tested_descriptors.difference(&accepted).count(), 125);
}

fn synth_bundle(blob: &[u8], ir_bytes: &[u8], leaf_index: usize) -> Vec<u8> {
    let proof_depth = u32::from_le_bytes(blob[24..28].try_into().expect("proof depth")) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().expect("proof offset")) as usize;
    let proof_base = proofs_off + leaf_index * proof_depth * 32;
    let mut bundle = Vec::with_capacity(2 + ir_bytes.len() + 8 + proof_depth * 32);
    bundle.extend_from_slice(&(ir_bytes.len() as u16).to_be_bytes());
    bundle.extend_from_slice(ir_bytes);
    bundle.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    bundle.extend_from_slice(&(proof_depth as u32).to_be_bytes());
    for index in 0..proof_depth {
        let offset = proof_base + index * 32;
        bundle.extend_from_slice(&blob[offset..offset + 32]);
    }
    bundle
}

fn normalize_text(text: &str) -> String {
    text.bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn normalized_rows(pages: &pqsigner_erc7730::display::Pages) -> Vec<String> {
    pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter())
        .filter_map(|row| {
            let text = std::str::from_utf8(row)
                .expect("PQ1 pages are ASCII")
                .trim_end();
            (!text.is_empty()).then(|| normalize_text(text))
        })
        .collect()
}

fn consume_normalized_token(rendered: &[String], cursor: &mut usize, expected: &str) {
    let normalized = normalize_text(expected);
    let Some(relative_match) = rendered[*cursor..]
        .iter()
        .position(|actual| actual == &normalized)
    else {
        panic!("expected token {expected:?} was not rendered in order; rows={rendered:?}");
    };
    *cursor += relative_match + 1;
}

fn consume_raw_word(rendered: &[String], cursor: &mut usize, word: &[u8; 32]) {
    let encoded = hex::encode(word);
    for chunk in encoded.as_bytes().chunks(16) {
        consume_normalized_token(
            rendered,
            cursor,
            std::str::from_utf8(chunk).expect("hex is ASCII"),
        );
    }
}

fn consume_full_address(rendered: &[String], cursor: &mut usize, address: &[u8; 20]) {
    let mut rows = [[b' '; DISPLAY_COLS]; 3];
    let [row1, row2, row3] = &mut rows;
    write_addr_full(row1, row2, row3, address);
    for row in rows {
        let text = std::str::from_utf8(&row)
            .expect("address rows are ASCII")
            .trim_end();
        consume_normalized_token(rendered, cursor, text);
    }
}

#[derive(Debug, Deserialize)]
struct WaiverFile {
    schema: u8,
    waivers: Vec<Waiver>,
}

#[derive(Clone, Debug, Deserialize)]
struct Waiver {
    fixture: String,
    case: usize,
    text_index: usize,
    text: String,
    class: String,
    reason: String,
}

fn case_waivers(fixture: &str, case: usize) -> BTreeMap<usize, Waiver> {
    let waiver_file: WaiverFile = serde_json::from_slice(
        &std::fs::read(fixture_root().join("conformance-waivers.json"))
            .expect("read conformance waivers"),
    )
    .expect("parse conformance waivers");
    assert_eq!(waiver_file.schema, 1);
    let projection_policy: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("projection-policy.json"))
            .expect("read projection policy"),
    )
    .expect("parse projection policy");
    let classes = projection_policy["presentation_classes"]
        .as_object()
        .expect("presentation classes");
    let mut waivers = BTreeMap::new();
    for waiver in waiver_file.waivers {
        assert!(!waiver.reason.trim().is_empty(), "waiver needs a rationale");
        assert!(
            classes.contains_key(&waiver.class),
            "unknown waiver class: {}",
            waiver.class
        );
        if waiver.fixture == fixture && waiver.case == case {
            assert!(
                waivers.insert(waiver.text_index, waiver).is_none(),
                "duplicate exact waiver"
            );
        }
    }
    waivers
}

#[test]
fn conformance_waivers_are_owned_only_by_enrolled_cases() {
    let waiver_file: WaiverFile = serde_json::from_slice(
        &std::fs::read(fixture_root().join("conformance-waivers.json"))
            .expect("read conformance waivers"),
    )
    .expect("parse conformance waivers");
    assert_eq!(waiver_file.schema, 1);
    let owners: BTreeSet<_> = waiver_file
        .waivers
        .iter()
        .map(|waiver| (waiver.fixture.as_str(), waiver.case))
        .collect();
    assert_eq!(
        owners,
        BTreeSet::from([
            (
                "registry/lido/tests/calldata-WithdrawalQueueERC721.tests.json",
                2usize,
            ),
            ("registry/lido/tests/calldata-wstETH.tests.json", 3usize,),
        ]),
        "a waiver for a non-enrolled case must fail the conformance lane"
    );
}

#[test]
fn lido_claim_positive_matches_actual_merkle_verified_pq1_pages_with_exact_waivers() {
    let relative_fixture = "registry/lido/tests/calldata-WithdrawalQueueERC721.tests.json";
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join(relative_fixture)).expect("read Lido fixture"),
    )
    .expect("parse Lido fixture");
    let case = &fixture["tests"][2];
    let raw_hex = case["rawTx"].as_str().expect("Lido rawTx");
    let raw = hex::decode(raw_hex.strip_prefix("0x").expect("0x rawTx")).expect("Lido rawTx hex");
    let parsed = eip1559::parse(&raw).expect("Lido fixture is a canonical unsigned type-2 tx");
    assert_eq!(parsed.tx.chain_id, 1);
    let to = parsed.tx.to.expect("Lido transaction target");

    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == parsed.tx.chain_id
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-WithdrawalQueueERC721.json")
        })
        .expect("accepted Lido descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify Lido descriptor");
    cross_check_contract(&verified.ir, parsed.tx.chain_id, &to).expect("bind Lido descriptor");
    let pages = render_erc7730_pages(
        &parsed.tx,
        parsed.data,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("render upstream Lido positive");

    let rendered = normalized_rows(&pages);
    let waivers = case_waivers(relative_fixture, 2);

    let expected = case["expectedTexts"]
        .as_array()
        .expect("Lido expectedTexts");
    let mut rendered_cursor = 0usize;
    let mut used_waivers = BTreeSet::new();
    for (text_index, expected) in expected.iter().enumerate() {
        let expected = expected.as_str().expect("expected text string");
        if let Some(waiver) = waivers.get(&text_index) {
            assert_eq!(
                waiver.text, expected,
                "waiver must pin the exact upstream token"
            );
            used_waivers.insert(text_index);
            continue;
        }
        if !expected.is_empty() && expected.bytes().all(|byte| byte.is_ascii_digit()) {
            let value: u64 = expected.parse().expect("fixture integer fits u64");
            let mut word = [0u8; 32];
            word[24..].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                parsed.data.get(4..36),
                Some(word.as_slice()),
                "upstream decimal must equal the exact signed calldata word"
            );
            let encoded = hex::encode(word);
            for chunk in encoded.as_bytes().chunks(16) {
                let chunk = std::str::from_utf8(chunk).expect("hex ASCII");
                let Some(relative_match) = rendered[rendered_cursor..]
                    .iter()
                    .position(|actual| actual == chunk)
                else {
                    panic!(
                        "PQ1 did not render the complete 256-bit word for {expected}; rows={rendered:?}"
                    );
                };
                rendered_cursor += relative_match + 1;
            }
            continue;
        }
        let normalized = normalize_text(expected);
        let Some(relative_match) = rendered[rendered_cursor..]
            .iter()
            .position(|actual| actual == &normalized)
        else {
            panic!(
                "unwaived upstream token {expected:?} was not present in order; PQ1 rows={rendered:?}"
            );
        };
        rendered_cursor += relative_match + 1;
    }
    assert_eq!(
        used_waivers.len(),
        waivers.len(),
        "unused waiver must fail the lane"
    );
    assert!(
        rendered.iter().any(|row| row == "claimwithdrawal")
            && rendered.iter().any(|row| row == "lidodao")
            && rendered.iter().any(|row| row == "requestid")
            && rendered.iter().any(|row| row == "000000000001c90f"),
        "non-vacuity: expected authenticated Lido semantics were not all rendered: {rendered:?}"
    );
}

#[test]
fn lido_withdrawal_queue_upstream_frontier_renders_nonpermit_request_and_transfers() {
    let relative_fixture = "registry/lido/tests/calldata-WithdrawalQueueERC721.tests.json";
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-WithdrawalQueueERC721.json")
        })
        .expect("accepted Lido WithdrawalQueue leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify Lido queue");
    cross_check_contract(&verified.ir, 1, &entry.contract).expect("bind Lido queue");

    let request_signature = "requestWithdrawals(uint256[],address)";
    let (_, raw) = fixture_case(relative_fixture, 0);
    let parsed = eip1559::parse(&raw).expect("canonical unsigned Lido request fixture");
    assert_eq!(parsed.tx.to, Some(entry.contract));
    assert_eq!(
        parsed.data.get(..4),
        Some(&keccak256(request_signature.as_bytes())[..4])
    );
    assert_eq!(parsed.data.len(), 132, "one array element plus owner");
    let owner: [u8; 20] = parsed.data[48..68].try_into().expect("request owner");
    assert_ne!(owner, [0u8; 20], "upstream fixture uses a literal owner");
    // The upstream amount has more nonzero fractional digits than PQ1's exact
    // scaled display budget. Without an independently supplied ERC-20 proof,
    // the renderer therefore shows the exact raw integer and token identity;
    // the verified-metadata path correctly refuses this particular value
    // instead of rounding it. Exact scaled positives are covered by the
    // production device-render test.
    let pages = render_erc7730_pages(
        &parsed.tx,
        parsed.data,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("render admitted Lido request fixture");
    let rendered = normalized_rows(&pages);
    assert!(
        rendered.iter().any(|row| row.contains("request"))
            && rendered.iter().any(|row| row.contains("withdraw")),
        "Lido request intent missing: {rendered:?}"
    );
    assert!(
        rendered.iter().any(|row| row == "1items"),
        "array count missing: {rendered:?}"
    );
    let mut owner_cursor = 0usize;
    consume_full_address(&rendered, &mut owner_cursor, &owner);

    for (case_index, signature) in [
        (
            1,
            "requestWithdrawalsWithPermit(uint256[],address,(uint256,uint256,uint8,bytes32,bytes32))",
        ),
        (3, "claimWithdrawals(uint256[],uint256[])"),
    ] {
        let (_, raw) = fixture_case(relative_fixture, case_index);
        let parsed = eip1559::parse(&raw).expect("canonical unsigned Lido fixture");
        assert_eq!(parsed.tx.to, Some(entry.contract));
        assert_eq!(parsed.data.get(..4), Some(&keccak256(signature.as_bytes())[..4]));
        assert!(matches!(
            render_erc7730_pages(
                &parsed.tx,
                parsed.data,
                &verified,
                None,
                &NameResolver::new(),
            ),
            Err(RenderErr::NoFormat)
        ));
    }

    for (case_index, signature) in [
        (4usize, "safeTransferFrom(address,address,uint256)"),
        (5, "transferFrom(address,address,uint256)"),
    ] {
        let (_, raw) = fixture_case(relative_fixture, case_index);
        let parsed = eip1559::parse(&raw).expect("canonical unsigned Lido transfer fixture");
        assert_eq!(parsed.tx.to, Some(entry.contract));
        assert_eq!(parsed.data.len(), 100, "selector plus three ABI words");
        assert_eq!(
            parsed.data.get(..4),
            Some(&keccak256(signature.as_bytes())[..4])
        );
        let from: [u8; 20] = parsed.data[16..36].try_into().expect("from address");
        let to: [u8; 20] = parsed.data[48..68].try_into().expect("to address");
        let request_id: [u8; 32] = parsed.data[68..100].try_into().expect("request ID word");
        let pages = render_erc7730_pages(
            &parsed.tx,
            parsed.data,
            &verified,
            None,
            &NameResolver::new(),
        )
        .expect("render admitted Lido transfer fixture");
        let rendered = normalized_rows(&pages);
        let mut cursor = 0usize;
        consume_normalized_token(&rendered, &mut cursor, "Transfer unstETH");
        consume_normalized_token(&rendered, &mut cursor, "NFT");
        consume_normalized_token(&rendered, &mut cursor, "From");
        consume_full_address(&rendered, &mut cursor, &from);
        consume_normalized_token(&rendered, &mut cursor, "To");
        consume_full_address(&rendered, &mut cursor, &to);
        consume_normalized_token(&rendered, &mut cursor, "Request ID");
        consume_raw_word(&rendered, &mut cursor, &request_id);
    }
}

#[test]
fn lido_claim_fixture_bundle_and_binding_mutations_fail_closed() {
    let (_, raw) = fixture_case(
        "registry/lido/tests/calldata-WithdrawalQueueERC721.tests.json",
        2,
    );
    let parsed = eip1559::parse(&raw).expect("Lido fixture is canonical unsigned Type-2");
    let to = parsed.tx.to.expect("Lido transaction target");
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == parsed.tx.chain_id
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-WithdrawalQueueERC721.json")
        })
        .expect("accepted Lido descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("fixture bundle verifies");

    let mut tampered_proof = bundle.clone();
    let proof_offset = 2 + entry.ir_bytes.len() + 8;
    assert!(
        proof_offset < tampered_proof.len(),
        "fixture proof is nonempty"
    );
    tampered_proof[proof_offset] ^= 0x01;
    assert_eq!(
        verify_erc7730_bundle(&tampered_proof, &registry.root).unwrap_err(),
        BundleError::Merkle,
        "one corpus-proof bit must invalidate the descriptor"
    );

    let mut trailing_bundle = bundle.clone();
    trailing_bundle.push(0);
    assert_eq!(
        verify_erc7730_bundle(&trailing_bundle, &registry.root).unwrap_err(),
        BundleError::TrailingBytes,
        "a valid corpus bundle plus one byte must not verify"
    );

    assert_eq!(
        cross_check_contract(&verified.ir, parsed.tx.chain_id.wrapping_add(1), &to),
        Err(BindingError::ChainIdMismatch)
    );
    let mut wrong_contract = to;
    wrong_contract[19] ^= 0x01;
    assert_eq!(
        cross_check_contract(&verified.ir, parsed.tx.chain_id, &wrong_contract),
        Err(BindingError::ContractMismatch)
    );
}

#[test]
fn lido_claim_fixture_calldata_mutations_refuse_or_render_boundary_exactly() {
    let (_, raw) = fixture_case(
        "registry/lido/tests/calldata-WithdrawalQueueERC721.tests.json",
        2,
    );
    let parsed = eip1559::parse(&raw).expect("Lido fixture is canonical unsigned Type-2");
    assert_eq!(parsed.data.len(), 36, "fixture is selector plus one word");
    let to = parsed.tx.to.expect("Lido transaction target");
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == parsed.tx.chain_id
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-WithdrawalQueueERC721.json")
        })
        .expect("accepted Lido descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("fixture bundle verifies");

    let mut short_tx = eip1559::parse(&raw)
        .expect("reparse short fixture shell")
        .tx;
    let short = &parsed.data[..parsed.data.len() - 1];
    short_tx.data_len = short.len();
    assert!(matches!(
        render_erc7730_pages(&short_tx, short, &verified, None, &NameResolver::new(),),
        Err(RenderErr::Reject("7730 short head"))
    ));

    let mut trailing = parsed.data.to_vec();
    trailing.push(0);
    let mut trailing_tx = eip1559::parse(&raw)
        .expect("reparse trailing fixture shell")
        .tx;
    trailing_tx.data_len = trailing.len();
    assert!(matches!(
        render_erc7730_pages(
            &trailing_tx,
            &trailing,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(RenderErr::Reject("7730 static calldata trailing"))
    ));

    let mut maximum = parsed.data.to_vec();
    maximum[4..36].fill(0xff);
    let maximum_tx = eip1559::parse(&raw)
        .expect("reparse maximum fixture shell")
        .tx;
    let maximum_pages =
        render_erc7730_pages(&maximum_tx, &maximum, &verified, None, &NameResolver::new())
            .expect("maximum request ID renders without clipping");
    let maximum_rows = normalized_rows(&maximum_pages);
    let mut maximum_cursor = 0usize;
    consume_normalized_token(&maximum_rows, &mut maximum_cursor, "Request ID");
    consume_raw_word(&maximum_rows, &mut maximum_cursor, &[0xff; 32]);

    let original_tx = eip1559::parse(&raw)
        .expect("reparse original fixture shell")
        .tx;
    let original_pages = render_erc7730_pages(
        &original_tx,
        parsed.data,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("original request ID renders");
    assert_ne!(
        normalized_rows(&original_pages),
        maximum_rows,
        "a boundary-magnitude mutation must change the trusted transcript"
    );
}

#[test]
fn serenita_deposit_and_exit_fixtures_match_corrected_pq1_semantics() {
    let relative_fixture = "registry/serenita/tests/calldata-EthVault.tests.json";
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join(relative_fixture)).expect("read Serenita fixture"),
    )
    .expect("parse Serenita fixture");
    assert_eq!(
        fixture["tests"][1]["description"].as_str(),
        Some("Stake ETH - chain 1")
    );
    assert_eq!(
        fixture["tests"][2]["description"].as_str(),
        Some("enter exit queue - chain 1")
    );
    assert_eq!(
        fixture["tests"][3]["description"].as_str(),
        Some("Update & Deposit - chain 1")
    );

    let registry = build_registry();
    let serenita_contract: [u8; 20] = hex::decode("b36fc5e542cb4fc562a624912f55da2758998113")
        .expect("Serenita contract hex")
        .try_into()
        .expect("Serenita contract width");
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == serenita_contract
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-EthVault.json")
        })
        .expect("accepted Serenita descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify Serenita leaf");
    cross_check_contract(&verified.ir, 1, &entry.contract).expect("bind Serenita descriptor");

    for case_index in [1usize, 2usize] {
        let (_, raw) = fixture_case(relative_fixture, case_index);
        let parsed = eip1559::parse(&raw).expect("canonical unsigned Serenita Type-2 fixture");
        assert_eq!(parsed.tx.chain_id, 1);
        assert_eq!(parsed.tx.to, Some(entry.contract));
        let pages = render_erc7730_pages(
            &parsed.tx,
            parsed.data,
            &verified,
            None,
            &NameResolver::new(),
        )
        .unwrap_or_else(|error| panic!("render Serenita fixture case {case_index}: {error:?}"));
        let rendered = normalized_rows(&pages);
        let mut cursor = 0usize;

        match case_index {
            1 => {
                assert_eq!(
                    &parsed.data[..4],
                    &keccak256(b"deposit(address,address)")[..4]
                );
                assert_eq!(
                    parsed.tx.value,
                    U256(
                        hex::decode(
                            "00000000000000000000000000000000000000000000000813ca56906d340000"
                        )
                        .expect("149 ETH word")
                        .try_into()
                        .expect("149 ETH word width")
                    )
                );
                let receiver: [u8; 20] = parsed.data[16..36]
                    .try_into()
                    .expect("Serenita receiver word");
                let referrer: [u8; 32] = parsed.data[36..68]
                    .try_into()
                    .expect("Serenita referrer word");
                assert_eq!(
                    receiver,
                    [
                        0xbd, 0x86, 0x07, 0x37, 0xf3, 0x2b, 0x7a, 0x43, 0xe1, 0x97, 0x37, 0x06,
                        0x06, 0xf7, 0xeb, 0x32, 0xc5, 0xca, 0xd3, 0x47,
                    ]
                );
                assert_eq!(referrer, [0u8; 32]);

                consume_normalized_token(&rendered, &mut cursor, "Stake ETH");
                consume_normalized_token(&rendered, &mut cursor, "Shares receiver");
                consume_full_address(&rendered, &mut cursor, &receiver);
                consume_normalized_token(&rendered, &mut cursor, "Amount to stake");
                consume_normalized_token(&rendered, &mut cursor, "149 ETH");
                consume_normalized_token(&rendered, &mut cursor, "Referrer");
                consume_raw_word(&rendered, &mut cursor, &referrer);
            }
            2 => {
                assert_eq!(
                    &parsed.data[..4],
                    &keccak256(b"enterExitQueue(uint256,address)")[..4]
                );
                let shares: [u8; 32] = parsed.data[4..36].try_into().expect("Serenita shares word");
                let receiver: [u8; 20] = parsed.data[48..68]
                    .try_into()
                    .expect("Serenita exit receiver word");

                consume_normalized_token(&rendered, &mut cursor, "Exit vault");
                consume_normalized_token(&rendered, &mut cursor, "Shares to exit");
                consume_raw_word(&rendered, &mut cursor, &shares);
                consume_normalized_token(&rendered, &mut cursor, "Exit receiver");
                consume_full_address(&rendered, &mut cursor, &receiver);
                assert!(
                    !rendered.iter().any(|row| {
                        row == "token(unverifi~" || row == "tokencontract" || row == "!raw,dec=?"
                    }),
                    "raw StakeWise shares must not acquire invented token semantics: {rendered:?}"
                );
            }
            _ => unreachable!(),
        }
    }

    let (_, refused_raw) = fixture_case(relative_fixture, 3);
    let refused = eip1559::parse(&refused_raw)
        .expect("canonical unsigned Serenita update-and-deposit fixture");
    assert_eq!(
        &refused.data[..4],
        &keccak256(b"updateStateAndDeposit(address,address,(bytes32,int160,uint160,bytes32[]))")
            [..4]
    );
    assert!(matches!(
        render_erc7730_pages(
            &refused.tx,
            refused.data,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(RenderErr::NoFormat)
    ));
}

#[test]
fn p2p_dynamic_string_mutations_refuse_noncanonical_tail() {
    let (_, raw) = fixture_case("registry/p2p/tests/calldata-P2pMessageSender.tests.json", 0);
    let parsed = eip1559::parse(&raw).expect("P2P fixture is canonical unsigned Type-2");
    assert_eq!(
        parsed.data.get(..4),
        Some(&keccak256(b"send(string)")[..4]),
        "fixture selector is send(string)"
    );
    let to = parsed.tx.to.expect("P2P transaction target");
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == parsed.tx.chain_id
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-P2pMessageSender.json")
        })
        .expect("accepted P2P descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("P2P bundle verifies");
    cross_check_contract(&verified.ir, parsed.tx.chain_id, &to).expect("bind P2P descriptor");
    assert!(matches!(
        render_erc7730_pages(
            &parsed.tx,
            parsed.data,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(RenderErr::Reject("7730 string not displayable"))
    ));

    const MESSAGE: &[u8; 16] = b"withdraw-keys-v1";
    let mut canonical = Vec::with_capacity(4 + 3 * 32);
    canonical.extend_from_slice(&parsed.data[..4]);
    let mut offset_word = [0u8; 32];
    offset_word[31] = 32;
    canonical.extend_from_slice(&offset_word);
    let mut length_word = [0u8; 32];
    length_word[31] = MESSAGE.len() as u8;
    canonical.extend_from_slice(&length_word);
    canonical.extend_from_slice(MESSAGE);
    canonical.extend_from_slice(&[0u8; 16]);
    assert_eq!(canonical.len(), 100, "selector plus one canonical ABI tail");

    let mut canonical_tx = eip1559::parse(&raw).expect("reparse P2P shell").tx;
    canonical_tx.data_len = canonical.len();
    let canonical_pages = render_erc7730_pages(
        &canonical_tx,
        &canonical,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("canonical short P2P message renders");
    let canonical_rows = normalized_rows(&canonical_pages);
    let mut canonical_cursor = 0usize;
    consume_normalized_token(&canonical_rows, &mut canonical_cursor, "Public keys");
    consume_normalized_token(
        &canonical_rows,
        &mut canonical_cursor,
        std::str::from_utf8(MESSAGE).expect("fixture message is ASCII"),
    );
    consume_normalized_token(&canonical_rows, &mut canonical_cursor, "16 bytes");

    let mut aliased = canonical.clone();
    aliased[35] = 0;
    let mut aliased_tx = eip1559::parse(&raw).expect("reparse alias shell").tx;
    aliased_tx.data_len = aliased.len();
    assert!(matches!(
        render_erc7730_pages(&aliased_tx, &aliased, &verified, None, &NameResolver::new(),),
        Err(RenderErr::Reject("7730 res offset != head end"))
    ));

    let mut truncated = canonical.clone();
    assert_eq!(truncated.pop(), Some(0));
    let mut truncated_tx = eip1559::parse(&raw).expect("reparse truncation shell").tx;
    truncated_tx.data_len = truncated.len();
    assert!(matches!(
        render_erc7730_pages(
            &truncated_tx,
            &truncated,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(RenderErr::Reject("7730 res pad oob"))
    ));

    let mut trailing = canonical;
    trailing.push(0);
    let mut trailing_tx = eip1559::parse(&raw).expect("reparse trailing shell").tx;
    trailing_tx.data_len = trailing.len();
    assert!(matches!(
        render_erc7730_pages(
            &trailing_tx,
            &trailing,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(RenderErr::Reject("7730 res not whole tail"))
    ));
}

fn render_adapted_contract_fixture(
    adapted: &AdaptedFixtureTx,
    source_name: &str,
    erc20: Option<&Erc20Metadata<'_>>,
) -> Vec<String> {
    let to = adapted.tx.to.expect("fixture transaction target");
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == adapted.tx.chain_id
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        })
        .unwrap_or_else(|| panic!("accepted descriptor leaf for {source_name}"));
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .unwrap_or_else(|_| panic!("Merkle-verify {source_name}"));
    cross_check_contract(&verified.ir, adapted.tx.chain_id, &to)
        .unwrap_or_else(|_| panic!("bind {source_name}"));
    let pages = render_erc7730_pages(
        &adapted.tx,
        &adapted.data,
        &verified,
        erc20,
        &NameResolver::new(),
    )
    .unwrap_or_else(|error| panic!("render {source_name}: {error:?}"));
    normalized_rows(&pages)
}

fn render_flat_eip712_fixture(encoded: &FlatStaticEip712, source_name: &str) -> Vec<String> {
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == encoded.chain_id
                && entry.contract == encoded.verifying_contract
                && entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        })
        .unwrap_or_else(|| panic!("accepted EIP-712 descriptor leaf for {source_name}"));
    assert_eq!(
        entry.primary_type_hash, encoded.primary_type_hash,
        "fixture must select the descriptor's exact primary type"
    );
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .unwrap_or_else(|_| panic!("Merkle-verify {source_name}"));
    cross_check_eip712(&verified.ir, encoded.chain_id, &encoded.domain_separator)
        .unwrap_or_else(|_| panic!("bind {source_name}"));
    let pages = render_erc7730_eip712_pages(
        encoded.chain_id,
        &encoded.verifying_contract,
        &encoded.primary_type_hash,
        &encoded.encoded_data,
        &verified,
        None,
        &NameResolver::new(),
    )
    .unwrap_or_else(|error| panic!("render {source_name}: {error:?}"));
    normalized_rows(&pages)
}

fn expected_static_word(ty: &str, expected: &str) -> [u8; 32] {
    let compact: String = expected
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let value = match ty {
        "bool" => Value::Bool(match compact.as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("upstream bool expected text is not canonical"),
        }),
        "address" | "bytes32" => Value::String(compact),
        _ if ty.starts_with("uint") => Value::String(compact),
        _ => panic!("unsupported expected flat-static type `{ty}`"),
    };
    fixture_static_word(ty, &value)
}

fn displayed_fixture_label(label: &str) -> String {
    assert!(label.is_ascii(), "upstream field label must be ASCII");
    if label.len() <= DISPLAY_COLS {
        return label.to_string();
    }
    let mut displayed = label.as_bytes()[..DISPLAY_COLS - 1].to_vec();
    displayed.push(b'~');
    String::from_utf8(displayed).expect("ASCII field label")
}

fn expected_flat_raw_transcript(
    protocol_header: &[&str],
    semantic_fields: &[(String, [u8; 32])],
) -> Vec<String> {
    let mut expected: Vec<String> = protocol_header
        .iter()
        .map(|row| normalize_text(row))
        .collect();

    for (label, word) in semantic_fields {
        let label = normalize_text(label);
        let encoded = hex::encode(word);
        let chunks: Vec<String> = encoded
            .as_bytes()
            .chunks(16)
            .map(|chunk| {
                std::str::from_utf8(chunk)
                    .expect("hex is ASCII")
                    .to_string()
            })
            .collect();
        assert_eq!(chunks.len(), 4, "a raw word renders as two exact pages");
        expected.extend([
            label.clone(),
            chunks[0].clone(),
            chunks[1].clone(),
            "1/2>next".to_string(),
            label,
            chunks[2].clone(),
            chunks[3].clone(),
            "2/2>next".to_string(),
        ]);
    }

    expected.extend(
        [
            "Network:",
            "Chain: 1",
            "(mainnet)",
            "> next",
            "L=cancel",
            "R=confirm",
        ]
        .iter()
        .map(|row| normalize_text(row)),
    );
    expected
}

fn normalized_transcript_is_exact(rendered: &[String], expected: &[String]) -> bool {
    rendered == expected
}

fn assert_flat_raw_eip712_fixture(
    relative_fixture: &str,
    source_name: &str,
    expected_protocol_header: &[&str],
    expected_members: &[(&str, &str)],
) -> Vec<String> {
    assert!(
        case_waivers(relative_fixture, 0).is_empty(),
        "flat raw enrollment must not acquire a presentation waiver"
    );
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join(relative_fixture)).expect("read EIP-712 fixture"),
    )
    .expect("parse EIP-712 fixture");
    let case = &fixture["tests"][0];
    let data = case["data"].as_object().expect("EIP-712 fixture data");
    let primary_type = data["primaryType"].as_str().expect("fixture primary type");
    let members = data["types"][primary_type]
        .as_array()
        .expect("fixture primary members");
    let actual_members: Vec<_> = members
        .iter()
        .map(|member| {
            (
                member["name"].as_str().expect("fixture member name"),
                member["type"].as_str().expect("fixture member type"),
            )
        })
        .collect();
    assert_eq!(
        actual_members, expected_members,
        "fixture member shape drift"
    );

    let encoded = encode_flat_static_eip712(data);
    assert_eq!(encoded.encoded_data.len(), expected_members.len() * 32);
    let rendered = render_flat_eip712_fixture(&encoded, source_name);
    let expected = case["expectedTexts"]
        .as_array()
        .expect("fixture expectedTexts");
    assert_eq!(expected.len(), expected_members.len() * 2);
    let message = data["message"].as_object().expect("fixture message");
    let mut semantic_fields = Vec::with_capacity(expected_members.len());
    for (field_index, ((name, ty), pair)) in expected_members
        .iter()
        .zip(expected.chunks_exact(2))
        .enumerate()
    {
        let label = displayed_fixture_label(pair[0].as_str().expect("upstream field label"));
        let signed_word: [u8; 32] = encoded.encoded_data[field_index * 32..(field_index + 1) * 32]
            .try_into()
            .expect("encoded EIP-712 word");
        assert_eq!(
            fixture_static_word(ty, &message[*name]),
            signed_word,
            "fixture message did not produce the signed `{name}` word"
        );
        assert_eq!(
            expected_static_word(ty, pair[1].as_str().expect("upstream expected field value")),
            signed_word,
            "upstream expected text did not bind the signed `{name}` word"
        );
        semantic_fields.push((label, signed_word));
    }
    let exact = expected_flat_raw_transcript(expected_protocol_header, &semantic_fields);
    assert!(
        normalized_transcript_is_exact(&rendered, &exact),
        "unexpected or missing normalized row for {source_name}; expected={exact:?}; rendered={rendered:?}"
    );
    rendered
}

#[test]
fn flat_raw_exact_transcript_rejects_an_injected_semantic_row() {
    let expected = expected_flat_raw_transcript(
        &["Protocol", "> next"],
        &[("Amount".to_string(), [0x11; 32])],
    );
    let mut injected = expected.clone();
    injected.insert(6, "unexpectedspender".to_string());
    assert!(
        !normalized_transcript_is_exact(&injected, &expected),
        "an unexpected semantic row must not pass as ignorable scaffolding"
    );
}

#[test]
fn smartcredit_flat_static_positive_matches_actual_merkle_verified_pq1_pages() {
    let rendered = assert_flat_raw_eip712_fixture(
        "registry/smartcredit/tests/eip712-smartcredit.tests.json",
        "eip712-smartcredit.json",
        &["SmartCredit.io", "SmartCredit", "> next"],
        &[
            ("collateralAddress", "address"),
            ("initialCollateralAmount", "uint256"),
            ("loanAmount", "uint256"),
            ("loanId", "bytes32"),
            ("loanInterestRate", "uint64"),
            ("loanTerm", "uint64"),
            ("underlyingAddress", "address"),
        ],
    );
    assert!(
        rendered.iter().any(|row| row == "smartcredit.io")
            && rendered.iter().any(|row| row == "loanid")
            && rendered.iter().any(|row| row == "0000000000000352")
            && rendered.iter().any(|row| row == "3d4e5f60718293ab"),
        "non-vacuity: authenticated SmartCredit semantics were not rendered: {rendered:?}"
    );
}

#[test]
fn pooltogether_bool_positive_matches_actual_merkle_verified_pq1_pages() {
    let rendered = assert_flat_raw_eip712_fixture(
        "registry/tally/tests/eip712-tally-ethereum-pooltogether-governor.tests.json",
        "eip712-tally-ethereum-pooltogether-governor.json",
        &["PoolTogether Gov", "ernor Alpha", "> next"],
        &[("proposalId", "uint256"), ("support", "bool")],
    );
    assert!(
        rendered.iter().any(|row| row == "proposalid")
            && rendered.iter().any(|row| row == "support")
            && rendered.iter().any(|row| row == "0000000000000003")
            && rendered.iter().any(|row| row == "0000000000000001"),
        "non-vacuity: authenticated PoolTogether bool semantics were not rendered: {rendered:?}"
    );
}

#[test]
fn tally_bravo_uint8_positive_matches_actual_merkle_verified_pq1_pages() {
    let rendered = assert_flat_raw_eip712_fixture(
        "registry/tally/tests/eip712-tally-ethereum-bravo-governor.tests.json",
        "eip712-tally-ethereum-bravo-governor.json",
        &["Uniswap Governor", "Uniswap Governo", "> next"],
        &[("proposalId", "uint256"), ("support", "uint8")],
    );
    assert!(
        rendered.iter().any(|row| row == "uniswapgovernor")
            && rendered.iter().any(|row| row == "proposalid")
            && rendered.iter().any(|row| row == "00000000000000b2")
            && rendered.iter().any(|row| row == "0000000000000001"),
        "non-vacuity: authenticated Tally Bravo uint8 semantics were not rendered: {rendered:?}"
    );
}

#[test]
fn signed_type2_threshold_positive_matches_actual_merkle_verified_pq1_pages() {
    let (fixture, raw) = fixture_case(
        "registry/threshold/tests/calldata-RebateStaking.tests.json",
        0,
    );
    let adapted = adapt_signed_type2_fixture(&raw);
    let rendered = render_adapted_contract_fixture(&adapted, "calldata-RebateStaking.json", None);
    let expected = fixture["tests"][0]["expectedTexts"]
        .as_array()
        .expect("Threshold expectedTexts");
    assert_eq!(expected.len(), 3);
    let mut cursor = 0usize;
    for token in expected {
        consume_normalized_token(
            &rendered,
            &mut cursor,
            token.as_str().expect("Threshold expected text"),
        );
    }
    assert_eq!(
        hex::encode(&adapted.data[4..]),
        "00000000000000000000000000000000000000000000003635c9adc5dea00000",
        "the displayed 1000 T amount must come from the complete signed calldata word"
    );
    assert!(
        rendered.iter().any(|row| row == "staket")
            && rendered.iter().any(|row| row == "thresholdnetwo")
            && rendered.iter().any(|row| row == "rebatestaking")
            && rendered.iter().any(|row| row == "1000t"),
        "non-vacuity: authenticated Threshold semantics were not all rendered: {rendered:?}"
    );
}

#[test]
fn legacy_lido_positive_matches_actual_merkle_verified_pq1_pages_with_exact_waivers() {
    let relative_fixture = "registry/lido/tests/calldata-wstETH.tests.json";
    let (fixture, raw) = fixture_case(relative_fixture, 3);
    let adapted = adapt_legacy_eip155_fixture(&raw);
    let records = dbgen::load_erc20_records(&workspace_root().join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let record = records
        .iter()
        .find(|record| {
            record.chain_id == adapted.tx.chain_id
                && dbgen::parse_hex_address(&record.address).ok() == adapted.tx.to
        })
        .expect("production wstETH metadata");
    assert_eq!(
        (
            record.name.as_str(),
            record.symbol.as_str(),
            record.decimals
        ),
        ("Wrapped liquid staked Ether 2.0", "wstETH", 18)
    );
    let metadata = Erc20Metadata {
        chain_id: record.chain_id,
        contract: adapted.tx.to.expect("wstETH target"),
        decimals: record.decimals,
        name: record.name.as_bytes(),
        symbol: record.symbol.as_bytes(),
    };
    let rendered =
        render_adapted_contract_fixture(&adapted, "calldata-wstETH.json", Some(&metadata));
    let expected = fixture["tests"][3]["expectedTexts"]
        .as_array()
        .expect("Lido wstETH expectedTexts");
    let waivers = case_waivers(relative_fixture, 3);
    assert_eq!(
        waivers.get(&3).map(|waiver| waiver.class.as_str()),
        Some("line_wrapped_address_like"),
        "the signed recipient waiver must retain its byte-binding class"
    );
    let mut used_waivers = BTreeSet::new();
    let mut cursor = 0usize;
    let recipient_word: [u8; 32] = adapted.data[4..36]
        .try_into()
        .expect("legacy transfer recipient word");
    for (text_index, token) in expected.iter().enumerate() {
        let token = token.as_str().expect("Lido wstETH expected text");
        if let Some(waiver) = waivers.get(&text_index) {
            assert_eq!(waiver.text, token, "waiver pins the exact upstream token");
            if waiver.class == "line_wrapped_address_like" {
                let compact: String = token
                    .chars()
                    .filter(|character| !character.is_ascii_whitespace())
                    .collect();
                assert_eq!(
                    hex::decode(compact.strip_prefix("0x").expect("upstream recipient 0x"))
                        .expect("upstream recipient hex")
                        .as_slice(),
                    &recipient_word[12..],
                    "the waived token must equal the signed recipient word"
                );
                let recipient_text = format!("0x{}", hex::encode(&recipient_word[12..]));
                for chunk in recipient_text.as_bytes().chunks(16) {
                    consume_normalized_token(
                        &rendered,
                        &mut cursor,
                        std::str::from_utf8(chunk).expect("address hex is ASCII"),
                    );
                }
            }
            used_waivers.insert(text_index);
            continue;
        }
        consume_normalized_token(&rendered, &mut cursor, token);
    }
    assert_eq!(used_waivers.len(), waivers.len(), "unused waiver must fail");
    assert_eq!(
        hex::encode(&adapted.data[36..68]),
        "000000000000000000000000000000000000000000000000000009184e72a000",
        "the exact 0.00001 wstETH amount must come from the signed calldata word"
    );
    assert!(
        rendered.iter().any(|row| row == "transferwsteth")
            && rendered.iter().any(|row| row == "lidodao")
            && rendered.iter().any(|row| row == "recipient")
            && rendered.iter().any(|row| row == "0.00001wsteth"),
        "non-vacuity: authenticated legacy Lido semantics were not all rendered: {rendered:?}"
    );
}

#[test]
fn lido_wsteth_inexact_upstream_calls_fail_closed() {
    let relative_fixture = "registry/lido/tests/calldata-wstETH.tests.json";
    let cases = [
        (0usize, "approve(address,uint256)", 1usize),
        (2, "unwrap(uint256)", 0),
        (4, "decreaseAllowance(address,uint256)", 1),
        (5, "increaseAllowance(address,uint256)", 1),
        (7, "transferFrom(address,address,uint256)", 2),
    ];

    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-wstETH.json")
        })
        .expect("accepted mainnet wstETH descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify wstETH leaf");
    cross_check_contract(&verified.ir, 1, &entry.contract).expect("bind wstETH descriptor");

    let records = dbgen::load_erc20_records(&workspace_root().join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let record = records
        .iter()
        .find(|record| {
            record.chain_id == 1
                && dbgen::parse_hex_address(&record.address).ok() == Some(entry.contract)
        })
        .expect("production wstETH metadata");
    let metadata = Erc20Metadata {
        chain_id: record.chain_id,
        contract: entry.contract,
        decimals: record.decimals,
        name: record.name.as_bytes(),
        symbol: record.symbol.as_bytes(),
    };
    assert_eq!(metadata.decimals, 18);

    for (case_index, signature, amount_word_index) in cases {
        let (_, raw) = fixture_case(relative_fixture, case_index);
        assert_eq!(supported_fixture_shell(&raw), FixtureShellKind::Type2);
        let (tx, data) = match rlp_field_count(&raw, true) {
            Some(9) => {
                let parsed = eip1559::parse(&raw).expect("canonical unsigned Type-2 fixture");
                let data = parsed.data.to_vec();
                (parsed.tx, data)
            }
            Some(12) => {
                let adapted = adapt_signed_type2_fixture(&raw);
                (adapted.tx, adapted.data)
            }
            fields => panic!("unexpected Type-2 field count for case {case_index}: {fields:?}"),
        };
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.to, Some(entry.contract));
        assert_eq!(tx.data_len, data.len());
        let selector = keccak256(signature.as_bytes());
        assert_eq!(&data[..4], &selector[..4], "fixture selector drift");

        let amount_offset = 4 + amount_word_index * 32;
        let amount = U256(
            data[amount_offset..amount_offset + 32]
                .try_into()
                .expect("complete static amount word"),
        );
        assert!(
            !amount_is_exact_at_fraction_digits(&amount, 18, 6),
            "fixture case {case_index} unexpectedly became exactly renderable"
        );
        assert!(
            matches!(
                render_erc7730_pages(&tx, &data, &verified, Some(&metadata), &NameResolver::new(),),
                Err(RenderErr::Reject("7730 inexact scaled value"))
            ),
            "case {case_index} must retain the existing exactness refusal"
        );
    }
}

#[test]
fn tally_uni_eip712_positive_matches_actual_merkle_verified_pq1_pages() {
    let relative_fixture = "registry/tally/tests/eip712-tally-ethereum-uni-token.tests.json";
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join(relative_fixture)).expect("read Tally UNI fixture"),
    )
    .expect("parse Tally UNI fixture");
    let case = &fixture["tests"][0];
    let data = case["data"].as_object().expect("Tally UNI EIP-712 data");
    let encoded = encode_flat_static_eip712(data);
    assert_eq!(encoded.chain_id, 1);
    assert_eq!(
        hex::encode(encoded.verifying_contract),
        "1f9840a85d5af5bf1d1762f925bdaddc4201f984"
    );
    assert_eq!(
        hex::encode(encoded.primary_type_hash),
        "e48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf"
    );
    assert_eq!(
        hex::encode(encoded.domain_separator),
        "28e9a6a663fbec82798f959fbf7b0805000a2aa21154d62a24be5f2a8716bf81"
    );
    assert_eq!(encoded.encoded_data.len(), 3 * 32);

    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == encoded.chain_id
                && entry.contract == encoded.verifying_contract
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("eip712-tally-ethereum-uni-token.json")
        })
        .expect("accepted Tally UNI descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify Tally UNI descriptor");
    cross_check_eip712(&verified.ir, encoded.chain_id, &encoded.domain_separator)
        .expect("bind Tally UNI EIP-712 descriptor");
    let pages = render_erc7730_eip712_pages(
        encoded.chain_id,
        &encoded.verifying_contract,
        &encoded.primary_type_hash,
        &encoded.encoded_data,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("render upstream Tally UNI positive");
    let rendered = normalized_rows(&pages);

    let expected = case["expectedTexts"]
        .as_array()
        .expect("Tally UNI expectedTexts");
    assert_eq!(expected.len(), 6);
    let mut cursor = 0usize;
    for (field_index, pair) in expected.chunks_exact(2).enumerate() {
        consume_normalized_token(
            &rendered,
            &mut cursor,
            pair[0].as_str().expect("expected field label"),
        );
        let expected_value = pair[1].as_str().expect("expected field value");
        let word: [u8; 32] = encoded.encoded_data[field_index * 32..(field_index + 1) * 32]
            .try_into()
            .expect("encoded EIP-712 word");
        if field_index == 0 {
            let compact: String = expected_value
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect();
            let address = hex::decode(compact.strip_prefix("0x").expect("expected address 0x"))
                .expect("expected address hex");
            assert_eq!(address.as_slice(), &word[12..]);
        } else {
            assert_eq!(fixture_u256_word(&pair[1]), word);
        }
        consume_raw_word(&rendered, &mut cursor, &word);
    }
    assert!(
        rendered.iter().any(|row| row == "unitoken")
            && rendered.iter().any(|row| row == "uniswap")
            && rendered.iter().any(|row| row == "delegatee")
            && rendered.iter().any(|row| row == "000000006b36ec80"),
        "non-vacuity: authenticated Tally UNI semantics were not all rendered: {rendered:?}"
    );
}

#[test]
fn tally_uni_eip712_length_and_boundary_mutations_are_injective() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(
            fixture_root().join("registry/tally/tests/eip712-tally-ethereum-uni-token.tests.json"),
        )
        .expect("read Tally UNI fixture"),
    )
    .expect("parse Tally UNI fixture");
    let data = fixture["tests"][0]["data"]
        .as_object()
        .expect("Tally UNI EIP-712 data");
    let encoded = encode_flat_static_eip712(data);
    assert_eq!(encoded.encoded_data.len(), 3 * 32);

    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == encoded.chain_id
                && entry.contract == encoded.verifying_contract
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("eip712-tally-ethereum-uni-token.json")
        })
        .expect("accepted Tally UNI descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Tally UNI bundle verifies");
    cross_check_eip712(&verified.ir, encoded.chain_id, &encoded.domain_separator)
        .expect("bind Tally UNI descriptor");

    let render = |encoded_data: &[u8]| {
        render_erc7730_eip712_pages(
            encoded.chain_id,
            &encoded.verifying_contract,
            &encoded.primary_type_hash,
            encoded_data,
            &verified,
            None,
            &NameResolver::new(),
        )
    };

    assert!(matches!(
        render(&encoded.encoded_data[..2 * 32]),
        Err(RenderErr::Reject("7730 ed len"))
    ));
    let mut hidden_member = encoded.encoded_data.clone();
    hidden_member.extend_from_slice(&[0u8; 32]);
    assert!(matches!(
        render(&hidden_member),
        Err(RenderErr::Reject("7730 ed len"))
    ));

    let zero_word = [0u8; 32];
    let mut zero_nonce = encoded.encoded_data.clone();
    zero_nonce[32..64].copy_from_slice(&zero_word);
    let zero_pages = render(&zero_nonce).expect("zero nonce renders exactly");
    let zero_rows = normalized_rows(&zero_pages);
    let mut zero_cursor = 0usize;
    consume_normalized_token(&zero_rows, &mut zero_cursor, "Nonce");
    consume_raw_word(&zero_rows, &mut zero_cursor, &zero_word);
    consume_normalized_token(&zero_rows, &mut zero_cursor, "Expiry");

    let maximum_word = [0xffu8; 32];
    let mut maximum_nonce = encoded.encoded_data.clone();
    maximum_nonce[32..64].copy_from_slice(&maximum_word);
    let maximum_pages = render(&maximum_nonce).expect("maximum nonce renders exactly");
    let maximum_rows = normalized_rows(&maximum_pages);
    let mut maximum_cursor = 0usize;
    consume_normalized_token(&maximum_rows, &mut maximum_cursor, "Nonce");
    consume_raw_word(&maximum_rows, &mut maximum_cursor, &maximum_word);
    consume_normalized_token(&maximum_rows, &mut maximum_cursor, "Expiry");

    assert_ne!(
        zero_rows, maximum_rows,
        "distinct boundary words must produce distinct trusted transcripts"
    );
}

#[test]
fn weth_upstream_positive_with_trailing_calldata_is_an_explicit_pq1_refusal() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("registry/weth/tests/calldata-weth.tests.json"))
            .expect("read WETH fixture"),
    )
    .expect("parse WETH fixture");
    let raw_hex = fixture["tests"][0]["rawTx"].as_str().expect("WETH rawTx");
    let raw = hex::decode(raw_hex.strip_prefix("0x").expect("0x rawTx")).expect("WETH rawTx hex");
    let parsed = eip1559::parse(&raw).expect("parse WETH transaction envelope");
    assert_eq!(parsed.data.len(), 5);
    assert_eq!(
        &parsed.data[..4],
        &pqsigner_tx_core::hash::keccak256(b"deposit()")[..4]
    );

    let to = parsed.tx.to.expect("WETH target");
    let registry = build_registry();
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == to
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-weth.json")
        })
        .expect("accepted WETH descriptor leaf");
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("Merkle-verify WETH descriptor");
    cross_check_contract(&verified.ir, parsed.tx.chain_id, &to).expect("bind WETH descriptor");
    assert!(matches!(
        render_erc7730_pages(
            &parsed.tx,
            parsed.data,
            &verified,
            None,
            &NameResolver::new(),
        ),
        Err(pqsigner_erc7730::render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));
}

#[test]
fn weth_canonical_deposit_and_withdraw_render_on_each_pinned_deployment() {
    fn value(raw: u64) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&raw.to_be_bytes());
        U256(bytes)
    }

    let registry = build_registry();
    let deposit_selector = &keccak256(b"deposit()")[..4];
    assert_eq!(deposit_selector, [0xd0, 0xe3, 0x0d, 0xb0]);
    let withdraw_selector = &keccak256(b"withdraw(uint256)")[..4];
    assert_eq!(withdraw_selector, [0x2e, 0x1a, 0x7d, 0x4d]);
    let records = dbgen::load_erc20_records(&workspace_root().join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    for (chain_id, address) in [
        (1, "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        (11_155_111, "fff9976782d46cc05630d1f6ebab18b2324d6b14"),
    ] {
        let contract: [u8; 20] = hex::decode(address)
            .expect("valid WETH9 address")
            .try_into()
            .expect("WETH9 address width");
        let entry = registry
            .entries
            .iter()
            .find(|entry| {
                entry.chain_id == chain_id
                    && entry.contract == contract
                    && entry.source.file_name().and_then(|name| name.to_str())
                        == Some("calldata-weth.json")
            })
            .expect("accepted WETH9 descriptor leaf");
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify WETH9 leaf");
        cross_check_contract(&verified.ir, chain_id, &contract).expect("bind WETH9 deployment");

        let render_deposit = |raw| {
            let tx = Eip1559Tx {
                chain_id,
                to: Some(contract),
                value: value(raw),
                data_len: deposit_selector.len(),
                ..Eip1559Tx::default()
            };
            let pages =
                render_erc7730_pages(&tx, deposit_selector, &verified, None, &NameResolver::new())
                    .expect("canonical four-byte WETH9 deposit renders");
            normalized_rows(&pages)
        };
        let half = render_deposit(500_000_000_000_000_000);
        let one = render_deposit(1_000_000_000_000_000_000);
        assert!(half.iter().any(|row| row == "0.5eth"), "rows={half:?}");
        assert!(one.iter().any(|row| row == "1eth"), "rows={one:?}");
        assert_ne!(
            half, one,
            "distinct signed values need distinct transcripts"
        );

        let record = records.iter().find(|record| {
            record.chain_id == chain_id
                && dbgen::parse_hex_address(&record.address).ok() == Some(contract)
        });
        let metadata = if chain_id == 1 {
            let record = record.expect("production mainnet WETH metadata");
            assert_eq!(
                (
                    record.name.as_str(),
                    record.symbol.as_str(),
                    record.decimals
                ),
                ("Wrapped Ether", "WETH", 18)
            );
            Some(Erc20Metadata {
                chain_id,
                contract,
                decimals: record.decimals,
                name: record.name.as_bytes(),
                symbol: record.symbol.as_bytes(),
            })
        } else {
            assert!(
                record.is_none(),
                "Sepolia WETH must not gain an unreviewed production metadata scale"
            );
            None
        };
        let render_withdraw = |raw| {
            let mut calldata = withdraw_selector.to_vec();
            calldata.extend_from_slice(&value(raw).0);
            let tx = Eip1559Tx {
                chain_id,
                to: Some(contract),
                data_len: calldata.len(),
                ..Eip1559Tx::default()
            };
            let pages = render_erc7730_pages(
                &tx,
                &calldata,
                &verified,
                metadata.as_ref(),
                &NameResolver::new(),
            )
            .expect("canonical WETH9 withdraw renders");
            (pages, calldata)
        };
        let (half_withdraw_pages, half_withdraw_calldata) =
            render_withdraw(500_000_000_000_000_000);
        assert_eq!(half_withdraw_calldata.len(), 36);
        assert_eq!(
            &half_withdraw_calldata[4..],
            &value(500_000_000_000_000_000).0,
            "the rendered amount must be the exact calldata word"
        );
        let half_withdraw = normalized_rows(&half_withdraw_pages);
        assert!(
            half_withdraw.iter().any(|row| row == "unwrap"),
            "withdraw intent is absent: {half_withdraw:?}"
        );
        let (one_withdraw_pages, _) = render_withdraw(1_000_000_000_000_000_000);
        let one_withdraw = normalized_rows(&one_withdraw_pages);
        assert_ne!(
            half_withdraw, one_withdraw,
            "distinct signed withdraw words need distinct transcripts"
        );
        if chain_id == 1 {
            assert!(
                half_withdraw.iter().any(|row| row == "0.5weth"),
                "mainnet metadata must scale the exact word as WETH: {half_withdraw:?}"
            );
            let mut cursor = 0;
            consume_full_address(&half_withdraw, &mut cursor, &contract);
        } else {
            assert!(
                half_withdraw.join("").contains("500000000000000000")
                    && half_withdraw.iter().any(|row| row == "!raw,dec=?"),
                "Sepolia without metadata must expose the exact raw amount: {half_withdraw:?}"
            );
            let mut cursor = 0;
            consume_full_address(&half_withdraw, &mut cursor, &contract);
        }
    }
}
