//! ERC-7730 clear-signing descriptor compiler.
//!
//! Reads JSON descriptors from a directory (one descriptor per file,
//! conforming to the ERC-7730 v2 schema at
//! <https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/specs/erc7730-v2.schema.json>),
//! records the ERC-8176 attestation provenance from `policy.toml`, and
//! emits one binary IR per `(chainId, contract)` deployment. The IRs
//! are Merkle-tree-hashed into `ERC7730_DESCRIPTORS_ROOT`, pinned in
//! `secure/src/db_roots.rs`.
//!
//! Wire layouts here match the on-device parser in
//! `pqsigner_erc7730::ir`. The 134-byte IR header uses **big-endian**
//! integers (unlike the LE-encoded ERC20 / Names / Selectors DBs); see
//! `docs/archive/handoff-erc7730-phase2.md` "Endianness flip" gotcha.
//!
//! ## Catalog blob layout (`tools/companion-stub/erc7730_db.bin`)
//!
//! ```text
//!   magic[4]              = "P730"
//!   version_le(4)         = ERC7730_DB_VERSION = 1
//!   flags_le(4)           = reserved (0)
//!   entry_cnt_le(4)
//!   ir_pool_off_le(4)
//!   ir_pool_size_le(4)
//!   proof_depth_le(4)
//!   proofs_off_le(4)
//!   // 32-byte header
//!
//!   entries[entry_cnt] (72 B each):
//!     chain_id_le(8) | contract(20) | primary_type_hash(32)
//!     | context_kind(1) | _pad(3) | ir_off_le(4) | ir_len_le(4)
//!
//!   ir_pool (concatenated IR bytes; ir_off is into this region)
//!
//!   proofs (entry_cnt * proof_depth * 32 bytes)
//! ```
//!
//! Sort order: `(chain_id, contract, primary_type_hash, context_kind)`.
//! Companion does a binary search by `(chain_id, to)` and emits the
//! trailer that `pqsigner_erc7730::bundle::verify_erc7730_bundle`
//! consumes.
//!
//! ## ERC-8176 policy
//!
//! Read from `secure/data/erc7730/policy.toml`. In dev mode
//! (`allow_unattested_dev_descriptors = true`) every descriptor is
//! accepted regardless of attestations and is marked `dev-unattested`
//! in every generated artifact. Production-mode plumbing accepts only a
//! hash-pinned offline snapshot whose EAS signatures, checkpoint header,
//! account/storage proofs, revocation state, and trusted-attester threshold
//! verify against the explicitly pinned ERC-8176 draft. The checked-in policy
//! deliberately has no such evidence yet, so canonical production generation
//! still refuses. An obsolete embedded `attestations` array is never evidence.

use crate::erc20::Erc20Capabilities;
use crate::erc8176::{
    load_and_verify_snapshot, SnapshotAnchor, VerifiedAttestationSet, ERC8176_DRAFT_COMMIT,
};
use crate::merkle::{node_hash, verify_proof, MerkleTree};
use pqsigner_erc7730::bundle::{leaf_hash, verify_erc7730_bundle_with_leaf_count, MAX_PROOF_DEPTH};
use pqsigner_erc7730::display::primitives::known_native_ticker;
use pqsigner_erc7730::forced_eligible::{
    ForcedEligibleSet, FORCED_ELIGIBLE_GROUP_LEN, FORCED_ELIGIBLE_HEADER_LEN,
    FORCED_ELIGIBLE_MAGIC, FORCED_ELIGIBLE_SCHEMA_V1, FORCED_ELIGIBLE_SELECTOR_LEN,
};
use pqsigner_erc7730::ir::{
    ContextKind, Erc7730Ir, FormatOp, CONTRACT_NAME_FIELD_LEN, CTX_CONTRACT, CTX_EIP712,
    ERC20_APPROVE_SELECTOR, HEADER_LEN, MAX_EIP712_STRING_PREIMAGES, MAX_FIELDS_PER_FORMAT,
    MAX_FORMATS, MAX_IR_LEN, MAX_NESTED_MEMBERS, OWNER_FIELD_LEN, SCHEMA_VER,
};
use pqsigner_erc7730::known_calls::{
    insert as insert_known_call, may_contain as known_call_may_contain, BLOOM_BYTES,
};
use pqsigner_erc7730::render::{
    calldata_policy::{
        calldata_field_slot, callee_location, lookup_parent, NestedCalldataEnrollment,
        NestedCalldataExecution, NestedCalldataParentKey, NestedCalleeLocation,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    },
    calldata_topology::{
        MAX_DYNAMIC_TAILS, TAIL_KIND_BLOB, TAIL_KIND_STATIC_WORD_ARRAY, TOPOLOGY_VERSION,
    },
    enums::ENUM_DISPLAY_BYTES,
    params::{NFT_COLLECTION_TO_PATH, PARAM_DYNAMIC_TAIL_TOPOLOGY},
    policy::{
        directly_displays_terminal, label_has_visible_glyph, token_path_displays_identity,
        validate_field as validate_field_policy, ParamMask, TerminalKind,
    },
};
use pqsigner_tx_core::hash::keccak256;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Recursive JSON syntax preflight that rejects duplicate object keys before
/// `serde_json::Value` can collapse them with last-write-wins semantics.
///
/// Descriptor hashes and `_pqsigner` admission policy are both derived from
/// the parsed value, so accepting two textual representations for one key
/// would let the discarded representation escape both validation and JCS
/// hashing. Object keys are compared after JSON unescaping.
struct RejectDuplicateJsonKeys;

impl<'de> Deserialize<'de> for RejectDuplicateJsonKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateJsonKeysVisitor)
    }
}

struct RejectDuplicateJsonKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateJsonKeysVisitor {
    type Value = RejectDuplicateJsonKeys;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element::<RejectDuplicateJsonKeys>()?
            .is_some()
        {}
        Ok(RejectDuplicateJsonKeys)
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            object.next_value::<RejectDuplicateJsonKeys>()?;
        }
        Ok(RejectDuplicateJsonKeys)
    }
}

fn contains_reserved_pqsigner_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.contains_key("_pqsigner") || object.values().any(contains_reserved_pqsigner_key)
        }
        serde_json::Value::Array(values) => values.iter().any(contains_reserved_pqsigner_key),
        _ => false,
    }
}

fn parse_json_value_rejecting_duplicate_keys(
    raw: &[u8],
) -> Result<serde_json::Value, serde_json::Error> {
    let mut preflight = serde_json::Deserializer::from_slice(raw);
    RejectDuplicateJsonKeys::deserialize(&mut preflight)?;
    preflight.end()?;
    let json: serde_json::Value = serde_json::from_slice(raw)?;

    // `_pqsigner` is an authority-narrowing extension, so silently ignoring a
    // correctly spelled block merely because it was nested under a permissive
    // upstream metadata/display object would restore the unrestricted
    // deployment × format cross-product. Each root or include is its own JSON
    // document: permit the reserved key only on that document's root object,
    // before include merging or JCS hashing.
    let misplaced = match &json {
        serde_json::Value::Object(root) => root.values().any(contains_reserved_pqsigner_key),
        other => contains_reserved_pqsigner_key(other),
    };
    if misplaced {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "reserved key `_pqsigner` may appear only at a JSON document root",
        ));
    }

    Ok(json)
}

// ─────────────────────────────────────────────────────────────────────
// Catalog header constants (mirrored from the other on-disk DBs).
// ─────────────────────────────────────────────────────────────────────

pub const ERC7730_DB_MAGIC: [u8; 4] = *b"P730";
pub const ERC7730_DB_VERSION: u32 = 1;
pub const ERC7730_DB_HEADER_LEN: usize = 32;
pub const ERC7730_DB_ENTRY_LEN: usize = 72;

/// Exact contract-call identity shared by the known-call inventory, the
/// clear-capable set recovered from `P730`, and the forced-eligible `P73K`
/// partition. Array ordering gives the canonical bytewise tuple order:
/// `(chain_id, target, selector)`.
pub type ContractCallTuple = (u64, [u8; 20], [u8; 4]);

const REVIEW_GENERATOR_HEADER: &str = "# Generated by `cargo run -p dbgen`. DO NOT EDIT BY HAND.\n";

/// Exact upstream identity stamped into the committed review artifact.
///
/// This receipt is review metadata, not release authority. The curation and
/// descriptor drift gates separately verify the full manifest and checked-in
/// corpus before accepting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryReviewSource {
    upstream_commit: String,
    upstream_tree: String,
    manifest_sha256: [u8; 32],
}

impl RegistryReviewSource {
    /// Construct a source stamp from an identity that the caller has already
    /// verified. This lets the xtask path reuse one immutable manifest snapshot
    /// rather than re-reading it after curation verification.
    pub fn new(
        upstream_commit: impl Into<String>,
        upstream_tree: impl Into<String>,
        manifest_sha256: [u8; 32],
    ) -> Result<Self, String> {
        let upstream_commit = upstream_commit.into();
        let upstream_tree = upstream_tree.into();
        validate_git_object_id(&upstream_commit, "upstream commit")?;
        validate_git_object_id(&upstream_tree, "upstream tree")?;
        Ok(Self {
            upstream_commit,
            upstream_tree,
            manifest_sha256,
        })
    }

    /// Digest of the exact curation manifest used to derive this source
    /// identity. Release status receipts bind this digest without reopening
    /// the manifest after the overlay was verified.
    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
}

#[derive(Debug, Deserialize)]
struct RegistryReviewManifest {
    upstream: RegistryReviewManifestUpstream,
}

#[derive(Debug, Deserialize)]
struct RegistryReviewManifestUpstream {
    commit: String,
    tree: String,
}

/// Read the exact manifest bytes and derive the source stamp used by
/// [`stamp_registry_review_source`]. Full manifest/corpus verification remains
/// owned by the curation gate; this helper makes the generated review header
/// deterministic and impossible to hand-type independently of the manifest.
pub fn load_registry_review_source(manifest_path: &Path) -> Result<RegistryReviewSource, String> {
    let bytes = fs::read(manifest_path).map_err(|error| {
        format!(
            "read ERC-7730 curation manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: RegistryReviewManifest = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "parse ERC-7730 curation manifest {} for review provenance: {error}",
            manifest_path.display()
        )
    })?;
    RegistryReviewSource::new(
        manifest.upstream.commit,
        manifest.upstream.tree,
        sha256_of(&bytes),
    )
}

/// Insert the manifest-derived upstream identity into a freshly rendered
/// review artifact. Re-stamping or a missing generator anchor is an error so a
/// caller cannot accidentally create an ambiguous provenance header.
pub fn stamp_registry_review_source(
    review_text: &mut String,
    source: &RegistryReviewSource,
) -> Result<(), String> {
    const STAMP_PREFIX: &str = "# Upstream registry commit: ";
    if review_text.contains(STAMP_PREFIX) {
        return Err("ERC-7730 review already carries an upstream source stamp".to_string());
    }
    let Some(anchor) = review_text.find(REVIEW_GENERATOR_HEADER) else {
        return Err("ERC-7730 review generator header is missing".to_string());
    };
    let insert_at = anchor + REVIEW_GENERATOR_HEADER.len();
    let stamp = format!(
        concat!(
            "# Upstream registry commit: {}\n",
            "# Upstream registry tree: {}\n",
            "# Curation manifest SHA-256: {}\n"
        ),
        source.upstream_commit,
        source.upstream_tree,
        hex::encode(source.manifest_sha256),
    );
    review_text.insert_str(insert_at, &stamp);
    Ok(())
}

fn validate_git_object_id(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly 40 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Pool TLV constants (Phase 5 walker MUST match these byte-for-byte).
// ─────────────────────────────────────────────────────────────────────

const PATHOP_ROOT_STRUCT: u8 = 0x10;
const PATHOP_ROOT_CONTAINER: u8 = 0x11;
const PATHOP_ROOT_METADATA: u8 = 0x12;
const PATHOP_FIELD_IDX: u8 = 0x20;
// Wire constants for the device-side path bytecode (canonical wire space shared
// with the on-device `PathOp` enum). In a rendered-VALUE path dbgen emits only
// ArrayAll (render every element of a bounded dynamic array) — single-index /
// slice / last are refused there (they would hide an array's other elements).
// ArrayIdx / ArraySlice
// / ArrayLast ARE emitted, but ONLY inside a `tokenAmount`'s `PARAM_TOKEN_PATH`
// TLV (token-IDENTITY extraction from a dynamic swap leg — Tier B, see
// `compile_token_path_extraction`), never in a rendered-value program. Encoding:
// ArrayIdx = op + u16 BE index; ArraySlice = op + u16 BE start + u16 BE len(=20) +
// 1 B from_end; ArrayLast = op. Device: `render::resolve::resolve_token_address`.
const PATHOP_ARRAY_IDX: u8 = 0x21;
const PATHOP_ARRAY_SLICE: u8 = 0x22;
const PATHOP_ARRAY_LAST: u8 = 0x23;
const PATHOP_ARRAY_ALL: u8 = 0x24;
/// Follow the ABI offset word at the current head slot into the calldata tail
/// (dynamic `bytes`/`string` and Tier-B token extraction). Multi-tail formats
/// authenticate the complete top-level partition separately; C2 dynamic-tuple
/// descent remains generator-refused.
/// Device: `render::resolve::resolve_structured`.
const PATHOP_FOLLOW_OFFSET: u8 = 0x25;

const FMT_RAW: u8 = 0x01;
const FMT_AMOUNT: u8 = 0x02;
const FMT_TOKEN_AMOUNT: u8 = 0x03;
const FMT_NFT_NAME: u8 = 0x04;
const FMT_DATE: u8 = 0x05;
const FMT_DURATION: u8 = 0x06;
const FMT_ADDRESS_NAME: u8 = 0x07;
const FMT_ENUM: u8 = 0x08;
const FMT_UNIT: u8 = 0x09;
const FMT_CALLDATA: u8 = 0x0A;
const FMT_CHAIN_ID: u8 = 0x0B;
const FMT_TOKEN_TICKER: u8 = 0x0C;
const FMT_INTEROP_ADDR_NAME: u8 = 0x0D;
const FMT_ENCRYPTED: u8 = 0x0E;
/// PQSigner-only complete renderer for an enrolled Router02 packed V3 path.
/// Merely naming this formatter never grants authority: `compile_one_format`
/// requires an exact descriptor/deployment/signature/selector enrollment.
const FMT_UNISWAP_V3_PATH: u8 = 0x0F;

const PARAM_TOKEN_PATH: u8 = 0x30;
const PARAM_TOKEN: u8 = 0x31;
const PARAM_THRESHOLD: u8 = 0x32;
const PARAM_MESSAGE: u8 = 0x33;
const PARAM_ADDR_TYPES: u8 = 0x34;
const PARAM_ADDR_SOURCES: u8 = 0x35;
const PARAM_DATE_ENCODING: u8 = 0x36;
const PARAM_ENUM_REF: u8 = 0x37;
const PARAM_DECIMALS: u8 = 0x38;
const PARAM_BASE: u8 = 0x39;
const PARAM_PREFIX: u8 = 0x3A;
#[allow(dead_code)] // wire-reserved; compiler rejects unsupported suffix semantics
const PARAM_SUFFIX: u8 = 0x3B;
const PARAM_NESTED_SELECTOR: u8 = 0x3C;
const PARAM_NESTED_CALLEE: u8 = 0x3D;
const PARAM_FALLBACK_LABEL: u8 = 0x3E;
const PARAM_VISIBILITY: u8 = 0x3F;
/// Constant annotation string for a path-less ERC-7730 field
/// (`{ "value": "...", "label": "...", "format": "raw" }`). The field is
/// not bound to calldata — it renders the literal (attested) string. Used
/// pervasively by the ERC-4626 / ERC-7540 vault templates.
const PARAM_CONST_VALUE: u8 = 0x40;

/// Format-level flag (parked on an EIP-712 format's first field) marking
/// that the primary type carries at least one nested struct member — a
/// single opaque `hashStruct` word the on-device renderer cannot expand.
/// The device declines the whole format to blind-sign on seeing it, so a
/// nested member (and any `address` inside it) is never partially
/// clear-signed or rendered as a garbage word
/// (`VULN-erc7730-eip712-nested-struct-address-hide`, on-device belt). The
/// build-time visibility gate is the primary defense; this is the
/// defense-in-depth backstop that survives a gate regression and is where
/// the future Phase-5 nested renderer will hook faithful expansion.
const PARAM_NESTED_STRUCT: u8 = 0x41;
// A `tokenAmount`'s `nativeCurrencyAddress`: the scalar form is one 20-byte
// sentinel; the registry list form is two descriptor-order addresses
// concatenated under the same tag. The old scalar encoding is byte-identical.
const PARAM_NATIVE_CURRENCY: u8 = 0x42;
/// ABI kind for a dynamic leaf. The device must not infer `string` versus
/// arbitrary `bytes` from whether attacker-controlled payload happens to be
/// printable.
const PARAM_DYNAMIC_KIND: u8 = 0x43;
/// `nftName.params.collection`: an exact descriptor-authenticated collection
/// contract. Kept distinct from tokenAmount's token vocabulary so malformed IR
/// cannot cross formatter semantics.
const PARAM_NFT_COLLECTION: u8 = 0x44;
/// `nftName.params.collectionPath`: a compiled static address path. The first
/// corpus-complete slice permits `@.to` and static structured address words.
const PARAM_NFT_COLLECTION_PATH: u8 = 0x45;
/// Format-level constrained `interpolatedIntent` bytecode. Canonically parked
/// on emitted field ordinal zero; source paths are resolved to field ordinals
/// at build time, so the device never interprets braces or JSON paths.
const PARAM_INTERPOLATED_INTENT: u8 = 0x46;
/// Schema-v5 authenticated terminal kind; mandatory on every field.
const PARAM_TERMINAL_KIND: u8 = 0x47;
/// Schema-v5 authenticated Solidity integer width in bytes. Emitted exactly
/// once for unsigned/signed integer terminals and forbidden for every other
/// terminal kind. Keeping this separate from the stable terminal-kind payload
/// preserves its one-byte wire shape while letting the device reject dirty
/// zero/sign extension on narrow integers.
const PARAM_INTEGER_WIDTH: u8 = 0x48;
/// Standard ERC-7730 `addressName.params.senderAddress` sentinel list. The
/// payload is one or more descriptor-order 20-byte addresses concatenated
/// without a count byte. Emission is gated by an exact semantic enrollment;
/// merely publishing `senderAddress` in a descriptor grants no substitution
/// authority.
const PARAM_SENDER_ADDRESS: u8 = 0x49;
/// Authenticated field-local ABI-word predicate. Payload:
/// `operation:u8 || canonical_word:[u8;32]`, where operation is one of the
/// `WORD_GUARD_*` constants below. The device evaluates every guard in a
/// format-wide preflight before painting trusted pages.
const PARAM_WORD_GUARD: u8 = 0x4A;
const WORD_GUARD_EQ: u8 = 0x00;
const WORD_GUARD_NE: u8 = 0x01;
const WORD_GUARD_PAYLOAD_LEN: usize = 33;
/// Authenticated singleton-domain predicate for a contract `bytes` leaf.
/// The zero-length payload is the complete wire meaning: the canonical sole
/// dynamic tail must contain exactly zero data bytes.  Dbgen emits this only
/// through an exact descriptor/deployment/signature/path enrollment.
const PARAM_EXACT_EMPTY_BYTES: u8 = 0x4B;
/// Schema-v6 ordinal selecting one exact preimage from the authenticated
/// EIP-712 evidence stream. Emission is restricted to the descriptor-,
/// deployment-, typehash-, and source-shape-bound enrollments below.
const PARAM_EIP712_STRING_PREIMAGE: u8 = 0x4C;
const MAX_SENDER_ADDRESSES: usize = 2;
const DYNAMIC_KIND_STRING: u8 = 0x01;
const DYNAMIC_KIND_BYTES: u8 = 0x02;
const INTERPOLATED_INTENT_VERSION: u8 = 0x01;
const MAX_INTERPOLATED_SUBSTITUTIONS: usize = 3;
const MAX_INTERPOLATED_INTENT_LEN: usize = 32;

/// Maximum EIP-712 struct nesting the gate will walk before failing closed.
/// Matches the on-device `ir::MAX_NESTING`; a type deeper than this (or a
/// malformed cyclic one) is refused rather than reasoned about.
const MAX_STRUCT_DEPTH: usize = 8;

// ─────────────────────────────────────────────────────────────────────
// Exact semantic enrollments.
// ─────────────────────────────────────────────────────────────────────

/// SHA-256(JCS(resolved descriptor JSON)) after both curated Router02 copies
/// gained their final visible value, full-route, and sender-semantic fields.
/// Any descriptor-byte semantic drift changes this binding and returns the
/// formats to fail-closed exclusion until an owner reviews and updates the
/// enrollment.
const ROUTER02_DESCRIPTOR_HASH: [u8; 32] = [
    0xa1, 0x35, 0x68, 0xdb, 0x5a, 0x0f, 0xe9, 0xae, 0xc5, 0xd6, 0xdd, 0x30, 0xbe, 0x22, 0x98, 0xba,
    0xc6, 0x96, 0x5c, 0x66, 0xda, 0x9d, 0x99, 0x9b, 0x2f, 0x10, 0x07, 0x2a, 0xfc, 0x13, 0xa6, 0x38,
];

/// SHA-256(JCS(resolved descriptor JSON)) for the curated Lido
/// WithdrawalQueueERC721 descriptor. The two batch-request routes may use the
/// standard zero-address `senderAddress` sentinel only while every descriptor
/// byte, deployment and selector still matches this reviewed enrollment.
const LIDO_QUEUE_DESCRIPTOR_HASH: [u8; 32] = [
    0x68, 0xf0, 0x49, 0x5c, 0x61, 0xd4, 0x94, 0x10, 0x0c, 0x46, 0x5a, 0x54, 0xbe, 0x6f, 0xdb, 0x26,
    0xb5, 0x4d, 0xb1, 0x86, 0x86, 0x48, 0xf9, 0x85, 0x38, 0x47, 0xda, 0xfa, 0xa4, 0x51, 0x9e, 0x1f,
];

/// SHA-256(JCS(resolved descriptor JSON)) for the curated Morpho Blue
/// descriptor.  The three callback-capable routes receive exact-empty
/// authority only while every descriptor byte and deployment still matches.
const MORPHO_BLUE_DESCRIPTOR_HASH: [u8; 32] = [
    0x4b, 0xd6, 0x9e, 0x28, 0x03, 0x0f, 0x0f, 0x5f, 0x36, 0xf4, 0x15, 0xa3, 0xad, 0x3c, 0x96, 0x46,
    0x42, 0xbf, 0xe5, 0xa0, 0xf2, 0x5d, 0x8a, 0x73, 0x39, 0x1a, 0x51, 0x7c, 0x45, 0x97, 0x74, 0x99,
];

/// SHA-256(JCS(resolved descriptor JSON)) for the curated Lombard mainnet
/// feeApproval descriptor. The contract constructs the signed struct with
/// `block.chainid`; this exact enrollment therefore guards the visible signed
/// `chainId` word against the authenticated deployment chain.
const LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH: [u8; 32] = [
    0xff, 0x31, 0xd7, 0x22, 0xaf, 0x07, 0x8f, 0xe8, 0xed, 0x04, 0x2f, 0x8f, 0xb4, 0x69, 0x95, 0xba,
    0x50, 0x77, 0x10, 0xb1, 0x59, 0x15, 0xba, 0xa5, 0xa6, 0xad, 0xfc, 0xc0, 0x79, 0x51, 0xb1, 0xa0,
];
const LOMBARD_FEE_APPROVAL_SOURCE_SUFFIX: &str =
    "registry/lombard/eip712-network-fee-authorization-mainnet.json";

const ROUTER02_MAINNET: [u8; 20] = [
    0x68, 0xb3, 0x46, 0x58, 0x33, 0xfb, 0x72, 0xa7, 0x0e, 0xcd, 0xf4, 0x85, 0xe0, 0xe4, 0xc7, 0xbd,
    0x86, 0x65, 0xfc, 0x45,
];
const LIDO_QUEUE_MAINNET: [u8; 20] = [
    0x88, 0x9e, 0xdc, 0x2e, 0xda, 0xb5, 0xf4, 0x0e, 0x90, 0x2b, 0x86, 0x4a, 0xd4, 0xd7, 0xad, 0xe8,
    0xe4, 0x12, 0xf9, 0xb1,
];
const MORPHO_BLUE: [u8; 20] = [
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x9c, 0xc5, 0xe9, 0x0e, 0x3b, 0x3a, 0xf6, 0x4b, 0xda, 0xf6, 0x2c,
    0x37, 0xee, 0xff, 0xcb,
];
const LOMBARD_LBTC_MAINNET: [u8; 20] = [
    0x82, 0x36, 0xa8, 0x70, 0x84, 0xf8, 0xb8, 0x43, 0x06, 0xf7, 0x20, 0x07, 0xf3, 0x6f, 0x26, 0x18,
    0xa5, 0x63, 0x44, 0x94,
];
const LOMBARD_FEE_APPROVAL_TYPE_HASH: [u8; 32] = [
    0x40, 0xac, 0x9f, 0x6a, 0xa2, 0x70, 0x75, 0xe6, 0x4c, 0x1e, 0xd1, 0xea, 0x2e, 0x83, 0x1b, 0x20,
    0xb8, 0xc2, 0x5e, 0xfd, 0xeb, 0x6b, 0x79, 0xfd, 0x0c, 0xf6, 0x83, 0xc9, 0xa9, 0xc5, 0x07, 0x25,
];
const ADDRESS_ZERO: [u8; 20] = [0u8; 20];
const ADDRESS_ONE: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ONE_WORD: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const ADDRESS_TWO_WORD: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
const ZERO_WORD: [u8; 32] = [0u8; 32];
const ROUTER02_SENDER_SENTINELS: [[u8; 20]; 1] = [ADDRESS_ONE];
const LIDO_QUEUE_SENDER_SENTINELS: [[u8; 20]; 1] = [ADDRESS_ZERO];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SemanticSenderEnrollment {
    path: &'static str,
    terminal_type: &'static str,
    sentinels: &'static [[u8; 20]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SemanticWordGuard {
    path: &'static str,
    terminal_type: &'static str,
    operation: u8,
    word: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SemanticFormatEnrollment {
    descriptor_hash: [u8; 32],
    chain_id: u64,
    contract: [u8; 20],
    canonical_signature: &'static str,
    selector: [u8; 4],
    sender: SemanticSenderEnrollment,
    guards: &'static [SemanticWordGuard],
    /// Permit the narrowly modeled dynamic `(bytes,address,uint256,uint256)`
    /// Router02 tuple and require exactly one full packed-path formatter.
    packed_v3_path: bool,
}

/// Exact authority for one or more EIP-712 signed-word predicates. Both the
/// source descriptor hash and the full primary type hash are pinned so a
/// source or encodeType drift cannot inherit the predicate silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Eip712WordGuardEnrollment {
    descriptor_hash: [u8; 32],
    chain_id: u64,
    contract: [u8; 20],
    canonical_signature: &'static str,
    type_hash: [u8; 32],
    deployment_chain_guard_path: Option<&'static str>,
    guards: &'static [SemanticWordGuard],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactEmptyBytesEnrollment {
    descriptor_hash: [u8; 32],
    chain_id: u64,
    contract: [u8; 20],
    canonical_signature: &'static str,
    selector: [u8; 4],
    path: &'static str,
}

/// One top-level typed-data `string` whose exact bytes may be supplied through
/// the descriptor-selected evidence stream. `ordinal` is evidence traversal
/// order, not the member's EIP-712 word index; the latter is independently
/// derived from the exact source path and signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Eip712StringPreimageFieldEnrollment {
    path: &'static str,
    ordinal: u8,
}

/// Narrow authority for displaying an EIP-712 string preimage. Every identity
/// component is exact: changing any descriptor byte, deployment, encodeType,
/// typehash, field set, ordering, or ordinal returns the format to the ordinary
/// opaque-hash refusal path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Eip712StringPreimageEnrollment {
    descriptor_hash: [u8; 32],
    chain_id: u64,
    contract: [u8; 20],
    canonical_signature: &'static str,
    type_hash: [u8; 32],
    fields: &'static [Eip712StringPreimageFieldEnrollment],
}

/// Production string-preimage authority is intentionally empty. Dynamic EIP-712
/// strings remain opaque hash words unless a future evidence-backed catalogue
/// reconciliation adds an exact descriptor/deployment/type/source enrollment.
const EIP712_STRING_PREIMAGE_ENROLLMENTS: [Eip712StringPreimageEnrollment; 0] = [];

const LOMBARD_FEE_APPROVAL_GUARDS: [SemanticWordGuard; 1] = [SemanticWordGuard {
    path: "chainId",
    terminal_type: "uint256",
    operation: WORD_GUARD_EQ,
    word: ONE_WORD,
}];

const EIP712_WORD_GUARD_ENROLLMENTS: [Eip712WordGuardEnrollment; 1] = [Eip712WordGuardEnrollment {
    descriptor_hash: LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH,
    chain_id: 1,
    contract: LOMBARD_LBTC_MAINNET,
    canonical_signature: "feeApproval(uint256 chainId,uint256 fee,uint256 expiry)",
    type_hash: LOMBARD_FEE_APPROVAL_TYPE_HASH,
    deployment_chain_guard_path: Some("chainId"),
    guards: &LOMBARD_FEE_APPROVAL_GUARDS,
}];

const ROUTER02_EXACT_INPUT_GUARDS: [SemanticWordGuard; 4] = [
    SemanticWordGuard {
        path: "params.recipient",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "params.amountIn",
        terminal_type: "uint256",
        operation: WORD_GUARD_NE,
        word: ZERO_WORD,
    },
    SemanticWordGuard {
        path: "params.sqrtPriceLimitX96",
        terminal_type: "uint160",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const ROUTER02_EXACT_OUTPUT_GUARDS: [SemanticWordGuard; 3] = [
    SemanticWordGuard {
        path: "params.recipient",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "params.sqrtPriceLimitX96",
        terminal_type: "uint160",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const ROUTER02_MULTIHOP_EXACT_INPUT_GUARDS: [SemanticWordGuard; 3] = [
    SemanticWordGuard {
        path: "to",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "amountIn",
        terminal_type: "uint256",
        operation: WORD_GUARD_NE,
        word: ZERO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const ROUTER02_MULTIHOP_EXACT_OUTPUT_GUARDS: [SemanticWordGuard; 2] = [
    SemanticWordGuard {
        path: "to",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const ROUTER02_PACKED_EXACT_INPUT_GUARDS: [SemanticWordGuard; 3] = [
    SemanticWordGuard {
        path: "params.recipient",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "params.amountIn",
        terminal_type: "uint256",
        operation: WORD_GUARD_NE,
        word: ZERO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const ROUTER02_PACKED_EXACT_OUTPUT_GUARDS: [SemanticWordGuard; 2] = [
    SemanticWordGuard {
        path: "params.recipient",
        terminal_type: "address",
        operation: WORD_GUARD_NE,
        word: ADDRESS_TWO_WORD,
    },
    SemanticWordGuard {
        path: "@.value",
        terminal_type: "uint256",
        operation: WORD_GUARD_EQ,
        word: ZERO_WORD,
    },
];

const SEMANTIC_FORMAT_ENROLLMENTS: [SemanticFormatEnrollment; 8] = [
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature:
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        selector: [0x04, 0xe4, 0x5a, 0xaf],
        sender: SemanticSenderEnrollment {
            path: "params.recipient",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_EXACT_INPUT_GUARDS,
        packed_v3_path: false,
    },
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature:
            "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        selector: [0x50, 0x23, 0xb4, 0xdf],
        sender: SemanticSenderEnrollment {
            path: "params.recipient",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_EXACT_OUTPUT_GUARDS,
        packed_v3_path: false,
    },
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature: "exactInput((bytes,address,uint256,uint256))",
        selector: [0xb8, 0x58, 0x18, 0x3f],
        sender: SemanticSenderEnrollment {
            path: "params.recipient",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_PACKED_EXACT_INPUT_GUARDS,
        packed_v3_path: true,
    },
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature: "exactOutput((bytes,address,uint256,uint256))",
        selector: [0x09, 0xb8, 0x13, 0x46],
        sender: SemanticSenderEnrollment {
            path: "params.recipient",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_PACKED_EXACT_OUTPUT_GUARDS,
        packed_v3_path: true,
    },
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature: "swapExactTokensForTokens(uint256,uint256,address[],address)",
        selector: [0x47, 0x2b, 0x43, 0xf3],
        sender: SemanticSenderEnrollment {
            path: "to",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_MULTIHOP_EXACT_INPUT_GUARDS,
        packed_v3_path: false,
    },
    SemanticFormatEnrollment {
        descriptor_hash: ROUTER02_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: ROUTER02_MAINNET,
        canonical_signature: "swapTokensForExactTokens(uint256,uint256,address[],address)",
        selector: [0x42, 0x71, 0x2a, 0x67],
        sender: SemanticSenderEnrollment {
            path: "to",
            terminal_type: "address",
            sentinels: &ROUTER02_SENDER_SENTINELS,
        },
        guards: &ROUTER02_MULTIHOP_EXACT_OUTPUT_GUARDS,
        packed_v3_path: false,
    },
    SemanticFormatEnrollment {
        descriptor_hash: LIDO_QUEUE_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: LIDO_QUEUE_MAINNET,
        canonical_signature: "requestWithdrawals(uint256[],address)",
        selector: [0xd6, 0x68, 0x10, 0x42],
        sender: SemanticSenderEnrollment {
            path: "#._owner",
            terminal_type: "address",
            sentinels: &LIDO_QUEUE_SENDER_SENTINELS,
        },
        guards: &[],
        packed_v3_path: false,
    },
    SemanticFormatEnrollment {
        descriptor_hash: LIDO_QUEUE_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: LIDO_QUEUE_MAINNET,
        canonical_signature: "requestWithdrawalsWstETH(uint256[],address)",
        selector: [0x19, 0xaa, 0x62, 0x57],
        sender: SemanticSenderEnrollment {
            path: "#._owner",
            terminal_type: "address",
            sentinels: &LIDO_QUEUE_SENDER_SENTINELS,
        },
        guards: &[],
        packed_v3_path: false,
    },
];

const EXACT_EMPTY_BYTES_ENROLLMENTS: [ExactEmptyBytesEnrollment; 6] = [
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: MORPHO_BLUE,
        canonical_signature:
            "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        selector: [0xa9, 0x9a, 0xad, 0x89],
        path: "#.data",
    },
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: MORPHO_BLUE,
        canonical_signature:
            "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        selector: [0x20, 0xb7, 0x6e, 0x81],
        path: "#.data",
    },
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 1,
        contract: MORPHO_BLUE,
        canonical_signature:
            "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
        selector: [0x23, 0x8d, 0x65, 0x79],
        path: "#.data",
    },
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 8_453,
        contract: MORPHO_BLUE,
        canonical_signature:
            "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        selector: [0xa9, 0x9a, 0xad, 0x89],
        path: "#.data",
    },
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 8_453,
        contract: MORPHO_BLUE,
        canonical_signature:
            "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        selector: [0x20, 0xb7, 0x6e, 0x81],
        path: "#.data",
    },
    ExactEmptyBytesEnrollment {
        descriptor_hash: MORPHO_BLUE_DESCRIPTOR_HASH,
        chain_id: 8_453,
        contract: MORPHO_BLUE,
        canonical_signature:
            "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
        selector: [0x23, 0x8d, 0x65, 0x79],
        path: "#.data",
    },
];

// Visibility byte values (matching `pqsigner_erc7730::ir::Visibility`).
const VIS_ALWAYS: u8 = 0x00;
const VIS_NEVER: u8 = 0x01;
const VIS_OPTIONAL: u8 = 0x02;
const VIS_IF_NOT_IN: u8 = 0x03;
const VIS_MUST_MATCH: u8 = 0x04;

// Address-type bitset (PARAM_ADDR_TYPES payload).
const ADDR_TYPE_WALLET: u8 = 0x01;
const ADDR_TYPE_EOA: u8 = 0x02;
const ADDR_TYPE_CONTRACT: u8 = 0x04;
const ADDR_TYPE_NFT_COLLECTION: u8 = 0x08;
const ADDR_TYPE_TOKEN: u8 = 0x10;
const ADDR_TYPE_COLLECTION: u8 = 0x20;

// Address-source bitset (PARAM_ADDR_SOURCES payload).
const ADDR_SRC_LOCAL: u8 = 0x01;
const ADDR_SRC_ENS: u8 = 0x02;
const ADDR_SRC_ETHERSCAN: u8 = 0x04;
const ADDR_SRC_REGISTRY: u8 = 0x08;

// Date-encoding (PARAM_DATE_ENCODING payload).
const DATE_ENC_TIMESTAMP: u8 = 0x00;
const DATE_ENC_BLOCKHEIGHT: u8 = 0x01;

// Maximum bytes per pool TLV payload — same cap the on-device walker
// uses (Phase 5 will enforce).
const MAX_POOL_TLV_PAYLOAD: usize = 254;
// Maximum bytes per path program. Single byte length prefix → 255.
const MAX_PATH_PROGRAM_LEN: usize = 255;

// ─────────────────────────────────────────────────────────────────────
// JSON shapes (subset of the ERC-7730 v2 schema we ingest today).
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    #[serde(rename = "$schema")]
    _schema: Option<String>,
    /// `includes` reference. Phase 2 rejects descriptors that use this
    /// field — the registry's templated permit / common-EIP712 entries
    /// land in Phase 3 once we wire the registry-mirror submodule.
    #[serde(default)]
    includes: Option<String>,
    /// Local, review-only annotation carried by the curated registry mirror.
    /// It has no rendering or policy semantics.
    #[serde(default)]
    _curation_note: Option<serde_json::Value>,
    /// PQSigner-local, fail-closed curation constraints. These can only narrow
    /// the ordinary descriptor deployment × format cross-product; they never
    /// add a deployment, format, selector, or runtime interpretation. The
    /// extension remains inside the JCS descriptor hash and the hash-bound
    /// full-file curation overlay.
    #[serde(rename = "_pqsigner", default)]
    pqsigner: Option<PqsignerCuration>,
    context: Context,
    metadata: Metadata,
    display: Display,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PqsignerCuration {
    /// Exact per-deployment format allowlists. When present, only listed
    /// deployment/format pairs may emit authenticated leaves. For contract
    /// contexts, unlisted source declarations remain in the independently
    /// generated known-call set and therefore continue to hard-refuse rather
    /// than becoming blind-signable. For EIP-712, an omitted deployment/type
    /// pair has no authenticated proof and cannot be selected for clear-signing.
    #[serde(rename = "deploymentFormats", default)]
    deployment_formats: Vec<DeploymentFormatAdmission>,
    /// Exact source formats that are intentionally retained only so their
    /// deployment/selector tuples enter the authenticated known-call refusal
    /// set for contract contexts, or so their full typed-data signatures stay
    /// explicitly quarantined for EIP-712. A refusal-only format can never emit
    /// an IR format, including through a later deployment allowlist edit.
    #[serde(rename = "refusalOnlyFormats", default)]
    refusal_only_formats: Vec<String>,
    /// Narrowing-only, per-deployment removal of a `tokenAmount` field's
    /// `threshold` / `message` shorthand. A descriptor shared by several
    /// deployments may carry an exact-max "Unlimited" claim that is source-true
    /// for one implementation but not another (Ethereum USDT keeps an exact-max
    /// allowance; Polygon USDT decrements it). Listing a deployment here
    /// compiles that deployment's IR without the claim, so it renders the exact
    /// value (or refuses) instead. It never adds a deployment, format, field,
    /// selector, or runtime interpretation; every entry must name a declared
    /// contract deployment and an existing direct `tokenAmount` field that
    /// really carries a threshold.
    #[serde(rename = "thresholdOmissions", default)]
    threshold_omissions: Vec<ThresholdOmission>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdOmission {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
    format: String,
    path: String,
}

/// Per-deployment `(format signature, field path)` pairs whose
/// threshold/message shorthand is removed (see [`ThresholdOmission`]).
type ThresholdOmissions = BTreeMap<(u64, [u8; 20]), BTreeSet<(String, String)>>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentFormatAdmission {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
    formats: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    #[serde(rename = "$id", default)]
    id: Option<String>,
    #[serde(default)]
    contract: Option<ContractContext>,
    #[serde(default)]
    eip712: Option<Eip712Context>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractContext {
    deployments: Vec<Deployment>,
    // `abi` field is deprecated in v2 — parameter names live in the
    // format key strings now. Model it explicitly so fail-closed unknown-field
    // handling does not drop the three legacy corpus descriptors that carry it.
    #[serde(rename = "abi", default)]
    _abi: Option<serde_json::Value>,
    /// Proposed context semantics that this offline firmware cannot authenticate.
    #[serde(default)]
    proxy: Option<serde_json::Value>,
    #[serde(rename = "stateRefs", default)]
    state_refs: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Eip712Context {
    #[serde(default)]
    deployments: Option<Vec<Deployment>>,
    #[serde(default)]
    domain: Option<Eip712Domain>,
    #[serde(rename = "domainSeparator", default)]
    domain_separator: Option<String>,
    /// Type schemas affect the signed-data interpretation. The current compiler
    /// derives supported shapes from format signatures, so accepting this while
    /// ignoring it would be fail-open.
    #[serde(default)]
    schemas: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
struct Eip712Domain {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(rename = "chainId", default)]
    chain_id: Option<u64>,
    #[serde(rename = "verifyingContract", default)]
    verifying_contract: Option<String>,
    #[serde(default)]
    salt: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Deployment {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
}

#[derive(Debug, Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    owner: Option<String>,
    /// Free-form `info` block (URL, deploymentDate, legalName, …). We
    /// surface it on the review file only; the on-device IR doesn't
    /// carry it.
    #[serde(default)]
    _info: Option<serde_json::Value>,
    #[serde(default)]
    constants: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    enums: Option<serde_json::Map<String, serde_json::Value>>,
    /// Per-descriptor token metadata used by the v2 spec to default
    /// `tokenAmount` decimals/symbol when no `tokenPath` is supplied.
    /// Phase 2 doesn't depend on this since the seed corpus carries
    /// explicit `tokenPath` everywhere.
    #[serde(default)]
    _token: Option<serde_json::Value>,
    #[serde(rename = "contractName", default)]
    contract_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Display {
    formats: BTreeMap<String, Format>,
    /// `$.display.definitions` — reusable field-format specs referenced by
    /// `fields[].$ref`. A definition is a format spec (label/format/params),
    /// never a path-bound field. Populated from the descriptor OR from an
    /// `includes` common file (the include deep-merge runs at the JSON layer
    /// before this deserializes, so both sources land here). See
    /// [`resolve_display_refs`]. (review finding 1.1)
    #[serde(default)]
    definitions: Option<BTreeMap<String, FieldDef>>,
}

#[derive(Debug, Deserialize, Clone)]
struct Format {
    #[serde(rename = "$id", default)]
    _id: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    fields: Vec<FieldDef>,
    /// v2 `interpolatedIntent`. The compiler emits only the fail-closed scalar
    /// amount subset; valid shapes outside that subset retain the static
    /// `intent` and carry no runtime interpolation program.
    #[serde(rename = "interpolatedIntent", default)]
    interpolated_intent: Option<String>,
    /// Catch-all for unmodelled top-level format keys (finding 1.3).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct FieldDef {
    /// Absent for a constant-annotation field (see `value`).
    #[serde(default)]
    path: Option<String>,
    /// Constant annotation string for a path-less field. Mutually
    /// exclusive with `path`. ERC-7730 allows `{ value, label, format }`
    /// with no path — a fixed (attested) string, not bound to calldata.
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    visible: Option<String>,
    /// `$ref` into `$.display.definitions.*` — a reference to a reusable
    /// format spec. The reference object carries its own `path`/`value`,
    /// and MAY override `label`/`visible`/`params` (params merge per-key,
    /// field wins); `format` always comes from the definition. Resolved by
    /// [`resolve_display_refs`] BEFORE flatten/compile so the completeness
    /// lint + compiler see the referenced format/params. Was silently
    /// dropped pre-fix → the field degraded to unlabeled raw hex (finding
    /// 1.1). Distinct from the `params.$ref` enum namespace
    /// (`$.metadata.enums.*`), which is resolved separately.
    #[serde(rename = "$ref", default)]
    ref_def: Option<String>,
    /// Nested field GROUP (ERC-7730 struct/tuple display). A field with a
    /// `fields` sub-array is a GROUP whose own `path` (e.g. `#.marketParams`)
    /// anchors its children's relative paths (e.g. `loanToken`); it carries no
    /// leaf `format`. [`flatten_field_groups`] expands a group into per-member
    /// leaf fields with combined paths (`#.marketParams.loanToken`) BEFORE any
    /// completeness / visibility / compile gate runs, so the on-device renderer
    /// (which addresses each ABI head-word slot individually) never sees the
    /// group node. Morpho Blue's `marketParams((address,address,address,address,
    /// uint256))` is the canonical case.
    #[serde(default)]
    fields: Option<Vec<FieldDef>>,
    /// `$id` — cosmetic field/group id; deserialize-and-ignore (modelled so it
    /// doesn't trip the 1.3 gate below).
    #[serde(rename = "$id", default)]
    _id: Option<serde_json::Value>,
    /// `separator` — cosmetic ARRAY-element separator (v2 schema: a string with
    /// an `{index}` placeholder used to join a rendered array's elements).
    /// dbgen renders each array element on its own page/row, so the join string
    /// is irrelevant — deserialize-and-ignore. Modelled (not gated): a purely
    /// cosmetic key must not drop a descriptor to blind-sign, and each element's
    /// value still renders individually (WYSIWYS holds). 0 corpus fields use it.
    #[serde(rename = "separator", default)]
    _separator: Option<serde_json::Value>,
    /// Catch-all for any field key NOT modelled above. A non-empty map means
    /// the descriptor uses a construct dbgen doesn't understand — historically
    /// that was silently dropped (e.g. `$ref` before it was modelled → the
    /// field degraded to unlabeled raw, finding 1.1). Now surfaced: the format
    /// is skipped-with-reason (tolerant) / hard-errors (strict) so an unmodelled
    /// key can't silently change what a trusted clear-sign renders (finding
    /// 1.3). The valid-but-SEMANTIC keys `encryption` (field is encrypted) and
    /// `iteration` (fieldGroup array display) are DELIBERATELY not modelled so
    /// they land here and skip-loud — dbgen implements neither, and rendering
    /// as if they were absent would mis-represent the signed data. params
    /// SUB-keys are still tolerated for forward-compat (a narrower surface).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────
// Policy.toml shape.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub min_attesters: usize,
    #[serde(default)]
    pub trusted_attesters: Vec<String>,
    #[serde(default)]
    pub allow_unattested_dev_descriptors: bool,
    /// Independently pinned input for the host-only ERC-8176 verifier.
    ///
    /// This table is deliberately absent from the checked-in dev policy. A
    /// production policy must bind both the snapshot bytes and the finalized
    /// Ethereum block hash used to authenticate its EIP-1186 proofs.
    #[serde(default)]
    pub erc8176_snapshot: Option<Erc8176SnapshotPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Erc8176SnapshotPolicy {
    /// Regular file relative to the policy file; absolute/parent paths refuse.
    pub path: PathBuf,
    /// SHA-256 of the exact snapshot bytes (lowercase `0x` hex).
    pub sha256: String,
    /// Independently reviewed finalized Ethereum block hash (lowercase `0x`).
    pub block_hash: String,
    pub block_number: u64,
    pub block_timestamp: u64,
    /// Explicit reproducible release-evaluation epoch; never the host clock.
    pub evaluation_time: u64,
    pub max_checkpoint_age_secs: u64,
    pub min_remaining_validity_secs: u64,
}

const MAX_ERC8176_POLICY_BYTES: u64 = 64 * 1024;

struct CatalogueEvidence {
    verified: VerifiedAttestationSet,
    policy_sha256: [u8; 32],
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let bytes = read_policy_bytes(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| format!("policy {} is not UTF-8: {e}", path.display()))?;
    toml::from_str(text).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn read_policy_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|e| format!("inspect policy {}: {e}", path.display()))?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        return Err(format!(
            "ERC-8176 policy {} must be a non-symlink regular file",
            path.display()
        ));
    }
    if before.len() > MAX_ERC8176_POLICY_BYTES {
        return Err(format!(
            "ERC-8176 policy {} is {} bytes; cap is {MAX_ERC8176_POLICY_BYTES}",
            path.display(),
            before.len()
        ));
    }

    let file = File::open(path).map_err(|e| format!("open policy {}: {e}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|e| format!("fstat policy {}: {e}", path.display()))?;
    if !after.file_type().is_file() {
        return Err(format!(
            "ERC-8176 policy {} changed to a non-regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(format!(
                "ERC-8176 policy {} changed between stat and open",
                path.display()
            ));
        }
    }

    let initial_capacity = usize::try_from(after.len())
        .unwrap_or(usize::MAX)
        .min(MAX_ERC8176_POLICY_BYTES as usize);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(MAX_ERC8176_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read policy {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_ERC8176_POLICY_BYTES {
        return Err(format!(
            "ERC-8176 policy {} grew beyond {MAX_ERC8176_POLICY_BYTES} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

fn load_policy_and_evidence(
    policy_path: &Path,
    force_production: bool,
) -> Result<(Policy, Option<CatalogueEvidence>, [u8; 32]), String> {
    let policy_bytes = read_policy_bytes(policy_path)?;
    let policy_sha256 = sha256_of(&policy_bytes);
    let policy_text = std::str::from_utf8(&policy_bytes)
        .map_err(|e| format!("policy {} is not UTF-8: {e}", policy_path.display()))?;
    let mut policy: Policy =
        toml::from_str(policy_text).map_err(|e| format!("parse {}: {e}", policy_path.display()))?;
    let configured_for_dev = policy.allow_unattested_dev_descriptors;
    if configured_for_dev && policy.erc8176_snapshot.is_some() {
        return Err(
            "dev-unattested ERC-7730 policy must not carry an ERC-8176 snapshot; use a distinct production policy and set allow_unattested_dev_descriptors = false"
                .to_string(),
        );
    }
    if force_production {
        policy.allow_unattested_dev_descriptors = false;
    }

    if policy.allow_unattested_dev_descriptors {
        return Ok((policy, None, policy_sha256));
    }

    if policy.min_attesters < 2 {
        return Err(format!(
            "production ERC-8176 policy requires min_attesters >= 2, got {}",
            policy.min_attesters
        ));
    }
    let trusted_attesters = parse_trusted_attesters(&policy.trusted_attesters)?;
    if policy.min_attesters > trusted_attesters.len() {
        return Err(format!(
            "production ERC-8176 policy requires {} attesters but configures only {} distinct trusted identities",
            policy.min_attesters,
            trusted_attesters.len()
        ));
    }

    let snapshot_policy = policy.erc8176_snapshot.as_ref().ok_or_else(|| {
        "production ERC-8176 policy is missing an independently pinned [erc8176_snapshot] input; obsolete descriptor-embedded `attestations` are not production evidence"
            .to_string()
    })?;
    if snapshot_policy.block_number == 0 || snapshot_policy.block_timestamp == 0 {
        return Err(
            "production ERC-8176 checkpoint block_number and block_timestamp must be nonzero"
                .to_string(),
        );
    }
    let snapshot_sha256 =
        parse_canonical_hex::<32>("erc8176_snapshot.sha256", &snapshot_policy.sha256)?;
    let checkpoint_block_hash =
        parse_canonical_hex::<32>("erc8176_snapshot.block_hash", &snapshot_policy.block_hash)?;
    let snapshot_path = resolve_policy_relative_snapshot(policy_path, &snapshot_policy.path)?;
    let anchor = SnapshotAnchor {
        snapshot_sha256,
        checkpoint_block_hash,
        checkpoint_block_number: snapshot_policy.block_number,
        evaluation_timestamp: snapshot_policy.evaluation_time,
        max_checkpoint_age_seconds: snapshot_policy.max_checkpoint_age_secs,
        min_remaining_validity_seconds: snapshot_policy.min_remaining_validity_secs,
    };
    let verified = load_and_verify_snapshot(&snapshot_path, &anchor, &trusted_attesters)
        .map_err(|e| format!("verify ERC-8176 snapshot {}: {e}", snapshot_path.display()))?;
    if verified.trusted_attesters() != &trusted_attesters {
        return Err("internal: verified ERC-8176 trust set differs from policy".to_string());
    }
    if verified.checkpoint_block_number() != snapshot_policy.block_number
        || verified.checkpoint_timestamp() != snapshot_policy.block_timestamp
    {
        return Err(format!(
            "ERC-8176 checkpoint identity mismatch: policy says block {} at {}, authenticated header says block {} at {}",
            snapshot_policy.block_number,
            snapshot_policy.block_timestamp,
            verified.checkpoint_block_number(),
            verified.checkpoint_timestamp(),
        ));
    }

    Ok((
        policy,
        Some(CatalogueEvidence {
            verified,
            policy_sha256,
        }),
        policy_sha256,
    ))
}

fn parse_trusted_attesters(values: &[String]) -> Result<BTreeSet<[u8; 20]>, String> {
    const PREFIX: &str = "eip155:1:0x";
    let mut out = BTreeSet::new();
    for (index, identity) in values.iter().enumerate() {
        let body = identity.strip_prefix(PREFIX).ok_or_else(|| {
            format!(
                "trusted_attesters[{index}] must be canonical mainnet CAIP-10 `{PREFIX}<40 lowercase hex>`"
            )
        })?;
        let address = parse_canonical_hex_body::<20>(&format!("trusted_attesters[{index}]"), body)?;
        if address == [0; 20] {
            return Err(format!("trusted_attesters[{index}] is the zero address"));
        }
        if !out.insert(address) {
            return Err(format!(
                "trusted_attesters[{index}] duplicates 0x{}",
                hex::encode(address)
            ));
        }
    }
    if out.is_empty() {
        return Err("production ERC-8176 trusted_attesters is empty".to_string());
    }
    Ok(out)
}

fn parse_canonical_hex<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} must use a lowercase 0x prefix"))?;
    parse_canonical_hex_body(label, body)
}

fn parse_canonical_hex_body<const N: usize>(label: &str, body: &str) -> Result<[u8; N], String> {
    if body.len() != N * 2
        || !body
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!(
            "{label} must contain exactly {} canonical lowercase hex digits",
            N * 2
        ));
    }
    let decoded = hex::decode(body).map_err(|e| format!("decode {label}: {e}"))?;
    let mut out = [0; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn resolve_policy_relative_snapshot(
    policy_path: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(
            "erc8176_snapshot.path must be a non-empty normal relative path without `.` or `..`"
                .to_string(),
        );
    }
    let policy_dir = policy_path
        .parent()
        .ok_or_else(|| "ERC-8176 policy path has no parent directory".to_string())?;
    let canonical_policy_dir = policy_dir.canonicalize().map_err(|e| {
        format!(
            "canonicalize policy directory {}: {e}",
            policy_dir.display()
        )
    })?;
    let candidate = policy_dir.join(relative);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|e| format!("inspect ERC-8176 snapshot {}: {e}", candidate.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "ERC-8176 snapshot {} must be a non-symlink regular file",
            candidate.display()
        ));
    }
    let canonical = candidate.canonicalize().map_err(|e| {
        format!(
            "canonicalize ERC-8176 snapshot {}: {e}",
            candidate.display()
        )
    })?;
    if !canonical.starts_with(&canonical_policy_dir) {
        return Err(format!(
            "ERC-8176 snapshot {} resolves outside its policy directory",
            candidate.display()
        ));
    }
    Ok(canonical)
}

/// Compile every `*.json` under `input_dir` with the policy at
/// `policy_path` BUT override `allow_unattested_dev_descriptors` per
/// `force_production`. `false` keeps the TOML value (currently the
/// explicitly labelled dev-unattested mode). `true` requires independently
/// pinned authenticated ERC-8176 snapshot evidence; it never falls back to the
/// obsolete descriptor-embedded `attestations` shape.
pub fn build_db_with_policy_override(
    input_dir: &Path,
    policy_path: &Path,
    force_production: bool,
    registry_root: Option<&Path>,
) -> Result<Erc7730BuildResult, String> {
    let capabilities = Erc20Capabilities::default();
    build_db_with_policy_override_and_erc20_capabilities(
        input_dir,
        policy_path,
        force_production,
        registry_root,
        &capabilities,
    )
}

/// Capability-aware variant of [`build_db_with_policy_override`]. Token-amount
/// interpolation is enrolled only when the deployment's static token identity
/// is present in this exact authenticated ERC-20 metadata set (or is a
/// firmware-pinned native identity).
pub fn build_db_with_policy_override_and_erc20_capabilities(
    input_dir: &Path,
    policy_path: &Path,
    force_production: bool,
    registry_root: Option<&Path>,
    erc20_capabilities: &Erc20Capabilities,
) -> Result<Erc7730BuildResult, String> {
    let (policy, evidence, policy_sha256) =
        load_policy_and_evidence(policy_path, force_production)?;
    build_db_inner(
        input_dir,
        &policy,
        evidence.as_ref(),
        policy_sha256,
        registry_root,
        false,
        &mut Vec::new(),
        erc20_capabilities,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

/// Explicit E2E/test-catalogue variant of
/// [`build_db_with_policy_override_and_erc20_capabilities`].
///
/// Ordinary and production catalogue entry points always compile against the
/// empty production nested-calldata table, even when the dbgen crate was built
/// with `nested-calldata-test-fixture`. Only this deliberately named route can
/// select the synthetic enrollment, which prevents a process that generates
/// production and E2E catalogues together from granting test authority to the
/// production output.
pub fn build_e2e_db_with_policy_override_and_erc20_capabilities(
    input_dir: &Path,
    policy_path: &Path,
    force_production: bool,
    registry_root: Option<&Path>,
    erc20_capabilities: &Erc20Capabilities,
) -> Result<Erc7730BuildResult, String> {
    let (policy, evidence, policy_sha256) =
        load_policy_and_evidence(policy_path, force_production)?;
    build_db_inner(
        input_dir,
        &policy,
        evidence.as_ref(),
        policy_sha256,
        registry_root,
        false,
        &mut Vec::new(),
        erc20_capabilities,
        e2e_nested_calldata_enrollments(),
    )
}

fn e2e_nested_calldata_enrollments() -> &'static [NestedCalldataEnrollment] {
    #[cfg(feature = "nested-calldata-test-fixture")]
    {
        pqsigner_erc7730::render::calldata_policy::TEST_NESTED_CALLDATA_ENROLLMENTS
    }
    #[cfg(not(feature = "nested-calldata-test-fixture"))]
    {
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS
    }
}

// ─────────────────────────────────────────────────────────────────────
// Public build result.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Emitted {
    pub source: PathBuf,
    pub descriptor_id: String,
    pub descriptor_hash: [u8; 32],
    /// ERC-8176 `descriptorHash` = keccak256(RFC-8785 JCS(resolved descriptor)).
    /// The EAS attestation binding (host-only; not in the device IR).
    pub erc8176_hash: [u8; 32],
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub context_kind: u8,
    pub primary_type_hash: [u8; 32],
    pub ir_bytes: Vec<u8>,
    pub leaf_index: usize,
}

pub struct Erc7730BuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub entries: Vec<Emitted>,
    pub review_text: String,
    pub leaf_count: usize,
    /// How the host compiler established trust in this exact leaf set.
    pub provenance: CatalogueProvenance,
    /// Firmware-pinned membership filter over every parsable contract call
    /// declared by the vendored registry (compiled or intentionally refused).
    /// This lets secure world detect that a hostile companion omitted the
    /// descriptor proof for a known `(chain, contract, selector)` tuple.
    pub known_calls_bloom: [u8; BLOOM_BYTES],
    pub known_call_count: usize,
    /// Exact canonical tuple set used to construct `known_calls_bloom`.
    ///
    /// The Bloom filter and its digest are compact firmware/receipt forms;
    /// neither can be inverted for an A/B registry review. Retaining the
    /// sorted tuples in the host-only build result lets `xtask diff-registry`
    /// distinguish a clear-signable call, a registry-known refusal, and a
    /// tuple that is absent from the compared registry without guessing from
    /// Bloom membership.
    pub known_calls: Vec<(u64, [u8; 20], [u8; 4])>,
    /// Canonical digest of the exact sorted tuple set used to construct the
    /// Bloom filter.  Bloom equality alone is not a faithfulness proof because
    /// collisions can hide a dropped tuple during registry vendoring.
    pub known_call_set_hash: [u8; 32],
    /// Canonical `P73K` encoding of `F = K ∖ C`, where `C` is recovered by
    /// strictly parsing the final emitted `P730` bytes rather than trusting
    /// the compiler's in-memory entry list. This fixed set is embedded in
    /// secure firmware only when the default-off forced-blind feature is on.
    pub forced_eligible_set: Vec<u8>,
    /// Number of strictly sorted `(chain, target)` groups in
    /// [`forced_eligible_set`](Self::forced_eligible_set).
    pub forced_eligible_group_count: usize,
    /// Number of exact `(chain, target, selector)` tuples in
    /// [`forced_eligible_set`](Self::forced_eligible_set).
    pub forced_eligible_count: usize,
    /// Number of accepted clear-capable contract-call tuples recovered from
    /// the final `P730` catalogue. Retained for release reporting only; callers
    /// must re-run [`prove_forced_eligible_partition`] before trusting it.
    pub clear_contract_call_count: usize,
    /// SHA-256 of the exact policy bytes read by this build. This is captured
    /// from the same immutable read used to parse and enforce the policy, so a
    /// release receipt never re-opens the path and accidentally binds a
    /// different file.
    pub policy_sha256: [u8; 32],
}

/// Machine-readable trust provenance emitted alongside every catalogue root.
///
/// `Erc8176Verified` is produced only from a pinned, authenticated offline
/// snapshot. The checked-in catalogue deliberately remains `DevUnattested`
/// until independent auditors populate that evidence and an owner rotates the
/// production root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogueProvenance {
    DevUnattested,
    Erc8176Verified,
}

impl CatalogueProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DevUnattested => "dev-unattested",
            Self::Erc8176Verified => "erc8176-verified",
        }
    }
}

/// Construct the canonical release receipt for one completed catalogue build.
///
/// `curation_input_sha256` is supplied by the already-verified overlay owner;
/// callers pass all zeroes for deliberately uncurated fixture/probe builds.
/// Every other field is derived from the exact in-memory build outputs, so the
/// receipt cannot accidentally bind files reopened after compilation.
pub fn catalogue_status_v1(
    result: &Erc7730BuildResult,
    curation_input_sha256: [u8; 32],
) -> Result<pqsigner_erc7730::catalogue_status::CatalogueStatusV1, String> {
    use pqsigner_erc7730::catalogue_status::{
        CatalogueProvenance as StatusProvenance, CatalogueStatusV1,
    };

    // P73S is the release binding for the exact K count/hash and final P730
    // identity. Refuse to mint it unless the independently decoded P73K
    // partition reconstructs that same K with no overlap or omission.
    prove_forced_eligible_partition(result)?;

    let leaf_count = u32::try_from(result.leaf_count)
        .map_err(|_| "ERC-7730 catalogue leaf count exceeds status-v1 u32".to_string())?;
    let catalogue_blob_size = u32::try_from(result.blob.len())
        .map_err(|_| "ERC-7730 catalogue blob exceeds status-v1 u32".to_string())?;
    let known_call_count = u32::try_from(result.known_call_count)
        .map_err(|_| "ERC-7730 known-call count exceeds status-v1 u32".to_string())?;
    let bloom_size = u32::try_from(result.known_calls_bloom.len())
        .map_err(|_| "ERC-7730 Bloom size exceeds status-v1 u32".to_string())?;
    let provenance = match result.provenance {
        CatalogueProvenance::DevUnattested => StatusProvenance::DevUnattested,
        CatalogueProvenance::Erc8176Verified => StatusProvenance::Erc8176Verified,
    };

    CatalogueStatusV1::new(
        ERC7730_DB_VERSION,
        SCHEMA_VER,
        provenance,
        leaf_count,
        catalogue_blob_size,
        known_call_count,
        bloom_size,
        result.root,
        sha256_of(&result.blob),
        result.known_call_set_hash,
        sha256_of(&result.known_calls_bloom),
        result.policy_sha256,
        curation_input_sha256,
        concat!("dbgen/", env!("CARGO_PKG_VERSION")).as_bytes(),
    )
    .map_err(|error| format!("encode ERC-7730 catalogue status v1: {error:?}"))
}

fn catalogue_provenance(
    policy: &Policy,
    evidence: Option<&CatalogueEvidence>,
) -> Result<CatalogueProvenance, String> {
    match (policy.allow_unattested_dev_descriptors, evidence) {
        (true, None) => Ok(CatalogueProvenance::DevUnattested),
        (false, Some(_)) => Ok(CatalogueProvenance::Erc8176Verified),
        (true, Some(_)) => Err(
            "internal: dev-unattested catalogue received ERC-8176 production evidence"
                .to_string(),
        ),
        (false, None) => Err(
            "production ERC-8176 catalogue is missing independently pinned, authenticated snapshot evidence; obsolete descriptor-embedded `attestations` are not accepted as production evidence"
                .to_string(),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Top-level build.
// ─────────────────────────────────────────────────────────────────────

/// Compile every `*.json` under `input_dir` against `policy_path` and
/// emit the catalog blob + Merkle root. Caller is expected to also
/// run `round_trip_check` before writing the artifacts to disk.
pub fn build_db(input_dir: &Path, policy_path: &Path) -> Result<Erc7730BuildResult, String> {
    let capabilities = Erc20Capabilities::default();
    build_db_with_erc20_capabilities(input_dir, policy_path, &capabilities)
}

/// Capability-aware variant of [`build_db`].
pub fn build_db_with_erc20_capabilities(
    input_dir: &Path,
    policy_path: &Path,
    erc20_capabilities: &Erc20Capabilities,
) -> Result<Erc7730BuildResult, String> {
    let (policy, evidence, policy_sha256) = load_policy_and_evidence(policy_path, false)?;
    build_db_inner(
        input_dir,
        &policy,
        evidence.as_ref(),
        policy_sha256,
        None,
        false,
        &mut Vec::new(),
        erc20_capabilities,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

/// Compile a SINGLE descriptor file, tolerantly. Returns the emitted IR
/// entries on success, or a descriptive reason on failure. Unlike
/// [`build_db`] this does NOT build a Merkle tree and does NOT hard-fail
/// the caller — it is the per-descriptor primitive behind the registry
/// coverage scan (`xtask scan-registry`), which tallies how much of the
/// upstream ERC-7730 registry the on-device renderer can clear-sign today
/// and groups the rest by why it was skipped. `registry_root` resolves
/// any `includes` templates (the registry repo root).
pub fn try_compile_one(
    path: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
) -> Result<Vec<Emitted>, String> {
    let capabilities = Erc20Capabilities::default();
    try_compile_one_with_erc20_capabilities(path, policy, registry_root, &capabilities)
}

/// Capability-aware variant of [`try_compile_one`].
pub fn try_compile_one_with_erc20_capabilities(
    path: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
    erc20_capabilities: &Erc20Capabilities,
) -> Result<Vec<Emitted>, String> {
    // A standalone coverage probe still needs the complete selector-signature
    // inventory for this descriptor (raw plus include-resolved views). That
    // keeps the public single-file path from bypassing the same collision gate
    // used by the full catalogue build.
    let mut declared_known_calls = BTreeSet::new();
    let mut declared_contract_signatures = DeclaredContractSignatures::new();
    let mut snapshot = DescriptorSourceSnapshot::default();
    let resolved = collect_declared_contract_calls(
        path,
        registry_root,
        &mut declared_known_calls,
        &mut declared_contract_signatures,
        &mut snapshot,
    )?;
    // The coverage scan reports whole-descriptor compilability (strict).
    compile_resolved_descriptor_with_nested_calldata_enrollments(
        path,
        &resolved,
        policy,
        false,
        &mut Vec::new(),
        erc20_capabilities,
        Some(&declared_contract_signatures),
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

/// A descriptor (or sub-tree) the tolerant build skipped, with why.
#[derive(Debug, Clone)]
pub struct SkipReport {
    pub source: PathBuf,
    pub reason: String,
}

/// Tolerant variant of [`build_db`] for the registry import (the corpus
/// switch). Recursively compiles every `calldata-*.json` / `eip712-*.json`
/// descriptor under `input_dir`. The independent known-call omission scan is
/// fail-closed: every selected or tripwired descriptor must be readable,
/// parseable, and have all `includes` resolved before tolerant renderer
/// compilation begins. After that preflight succeeds, renderer-policy failures
/// and byte-identical duplicate leaves are SKIPPED with a [`SkipReport`] rather
/// than hard-failing the whole build. The surviving leaves are
/// Merkle-tree-hashed exactly as the strict build, so the resulting root is a
/// faithful catalog of "everything the on-device renderer can clear-sign from
/// this registry" without permitting a broken descriptor to disappear from
/// omission protection. `registry_root` resolves `includes` templates.
pub fn build_db_tolerant(
    input_dir: &Path,
    policy_path: &Path,
    registry_root: Option<&Path>,
) -> Result<(Erc7730BuildResult, Vec<SkipReport>), String> {
    let capabilities = Erc20Capabilities::default();
    build_db_tolerant_with_erc20_capabilities(input_dir, policy_path, registry_root, &capabilities)
}

/// Capability-aware variant of [`build_db_tolerant`].
pub fn build_db_tolerant_with_erc20_capabilities(
    input_dir: &Path,
    policy_path: &Path,
    registry_root: Option<&Path>,
    erc20_capabilities: &Erc20Capabilities,
) -> Result<(Erc7730BuildResult, Vec<SkipReport>), String> {
    let (policy, evidence, policy_sha256) = load_policy_and_evidence(policy_path, false)?;
    let mut skips: Vec<SkipReport> = Vec::new();
    let result = build_db_inner(
        input_dir,
        &policy,
        evidence.as_ref(),
        policy_sha256,
        registry_root,
        true,
        &mut skips,
        erc20_capabilities,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )?;
    Ok((result, skips))
}

/// Recursively collect standalone ERC-7730 descriptor files (the same
/// `calldata-*` / `eip712-*` filter the scanner uses), skipping `tests/`
/// fixture dirs and `*.tests.*` include-templates.
fn collect_descriptors(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("read entry under {}: {e}", dir.display()))?;
        let p = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("file type {}: {e}", p.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is not allowed in descriptor corpus: {}",
                p.display()
            ));
        }
        if file_type.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_descriptors(&p, out)?;
        } else if file_type.is_file() {
            let name = utf8_regular_file_name(&p)?;
            if name.ends_with(".json")
                && !name.contains(".tests.")
                && (name.starts_with("calldata-") || name.starts_with("eip712-"))
            {
                out.push(p);
            }
        }
    }
    Ok(())
}

/// Collect every canonical lowercase `*.json` file not selected by the
/// `calldata-*` / `eip712-*` renderer naming convention. These are still
/// omission-filter inputs: a misnamed child may declare deployments while an
/// include supplies every format, so raw substring classification is unsafe.
/// Concrete descriptor classification happens only after JSON parsing and
/// include resolution in [`build_db_inner`].
fn collect_unscanned_json_files(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    renderer_scope: bool,
    under_tests_dir: bool,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(dir)
        .map_err(|e| format!("inspect descriptor directory {}: {e}", dir.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symlink is not allowed as a descriptor corpus root: {}",
            dir.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "descriptor corpus path is not a directory: {}",
            dir.display()
        ));
    }
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("read entry under {}: {e}", dir.display()))?;
        let p = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("file type {}: {e}", p.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is not allowed in descriptor corpus: {}",
                p.display()
            ));
        }
        if file_type.is_dir() {
            // Test-fixture naming is not a security boundary. A descriptor
            // moved beneath `tests/` must stop being render-authoritative, but
            // its declared calls must remain in the omission filter.
            let child_is_tests = p.file_name().is_some_and(|name| name == "tests");
            collect_unscanned_json_files(
                &p,
                out,
                renderer_scope,
                under_tests_dir || child_is_tests,
            )?;
        } else if file_type.is_file() {
            let name = utf8_regular_file_name(&p)?;
            if name.to_ascii_lowercase().ends_with(".json") && !name.ends_with(".json") {
                return Err(format!(
                    "non-canonical JSON filename `{name}` — use lowercase `.json` so the security scanner cannot omit it"
                ));
            }
            let scanned = renderer_scope
                && !under_tests_dir
                && name.ends_with(".json")
                && !name.contains(".tests.")
                && (name.starts_with("calldata-") || name.starts_with("eip712-"));
            if name.ends_with(".json") && !scanned {
                out.push(p);
            }
        }
    }
    Ok(())
}

/// Return the UTF-8 spelling of a regular-file name or fail closed.
///
/// The registry naming convention is security-relevant: it selects which
/// descriptors enter both the renderer catalogue and the independent known-call
/// omission scan. Silently skipping a non-UTF-8 name would therefore create an
/// unaudited coverage hole. Keep this diagnostic path-independent so committed
/// receipts and tests do not disclose or depend on a checkout directory.
fn utf8_regular_file_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            "non-UTF-8 regular-file name in descriptor corpus — refusing to skip it".to_string()
        })
}

fn build_db_inner(
    input_dir: &Path,
    policy: &Policy,
    evidence: Option<&CatalogueEvidence>,
    policy_sha256: [u8; 32],
    registry_root: Option<&Path>,
    tolerant: bool,
    skips: &mut Vec<SkipReport>,
    erc20_capabilities: &Erc20Capabilities,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Result<Erc7730BuildResult, String> {
    // Establish provenance once for the entire leaf set. This deliberately
    // fails before reading any descriptor when production evidence is absent,
    // so no legacy embedded-attester shape can be mistaken for verification.
    let provenance = catalogue_provenance(policy, evidence)?;

    // The strict path keeps its flat, name-agnostic read (our hand-authored
    // corpus is a flat dir of `*.json`); the tolerant path walks the
    // registry's nested `registry/<project>/` tree and filters to real
    // descriptor files.
    let mut unscanned_declared_sources: Vec<PathBuf> = Vec::new();
    let mut sources: Vec<PathBuf> = if tolerant {
        let mut v = Vec::new();
        collect_descriptors(input_dir, &mut v)?;
        // Filename-convention tripwire (review 2.3): every unselected JSON is
        // still parsed, include-resolved, and omission-scanned below. A
        // concrete resolved descriptor also receives a visible skip receipt.
        let mut unscanned = Vec::new();
        collect_unscanned_json_files(input_dir, &mut unscanned, true, false)?;
        // `ercs/` is a sibling support corpus, not a renderer input. It is
        // nevertheless security-relevant: a template can itself declare a
        // deployment, or a child merge can replace that deployment. Scan every
        // JSON conservatively so vendoring/receipting `ercs` cannot hide a call
        // from the omission filter.
        if let Some(root) = registry_root {
            let ercs = root.join("ercs");
            match fs::symlink_metadata(&ercs) {
                Ok(_) if !ercs.starts_with(input_dir) => {
                    collect_unscanned_json_files(&ercs, &mut unscanned, false, false)?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect sibling ercs corpus {}: {error}",
                        ercs.display()
                    ));
                }
            }
        }
        unscanned.sort();
        unscanned.dedup();
        for p in unscanned {
            unscanned_declared_sources.push(p);
        }
        v
    } else {
        let mut strict_sources = Vec::new();
        for entry in
            fs::read_dir(input_dir).map_err(|e| format!("read_dir {}: {e}", input_dir.display()))?
        {
            let entry =
                entry.map_err(|e| format!("read entry under {}: {e}", input_dir.display()))?;
            let p = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| format!("file type {}: {e}", p.display()))?;
            if file_type.is_symlink() {
                return Err(format!(
                    "symlink is not allowed in descriptor corpus: {}",
                    p.display()
                ));
            }
            if file_type.is_file() {
                let name = utf8_regular_file_name(&p)?;
                if name.ends_with(".json") {
                    strict_sources.push(p);
                }
            }
        }
        strict_sources
    };
    sources.sort();

    if sources.is_empty() {
        return Err(format!(
            "no .json descriptors found under {}",
            input_dir.display()
        ));
    }

    let mut emitted: Vec<Emitted> = Vec::with_capacity(sources.len() * 2);
    // Omission policy is intentionally broader than renderer coverage. Every
    // selected descriptor must parse and resolve; then every parsable contract
    // tuple declared by the vendored registry is "known", even when its format
    // is later rejected by strict WYSIWYS compilation. Otherwise an
    // unsupported/high-risk or broken registry shape could silently regain a
    // blind-sign path merely because the safer compiler dropped it.
    let mut declared_known_calls = BTreeSet::<ContractCallKey>::new();
    let mut declared_contract_signatures = DeclaredContractSignatures::new();
    let mut declared_refusal_only_calls = DeclaredRefusalOnlyCalls::new();
    let mut source_snapshot = DescriptorSourceSnapshot::default();
    let mut resolved_sources = BTreeMap::<PathBuf, serde_json::Value>::new();
    for src in &unscanned_declared_sources {
        let resolved = collect_declared_contract_calls(
            src,
            registry_root,
            &mut declared_known_calls,
            &mut declared_contract_signatures,
            &mut source_snapshot,
        )
        .map_err(|e| omission_scan_error(src, input_dir, registry_root, &e))?;
        collect_declared_refusal_only_calls(&resolved, &mut declared_refusal_only_calls)
            .map_err(|e| omission_scan_error(src, input_dir, registry_root, &e))?;
        if has_concrete_descriptor_shape(&resolved) {
            skips.push(SkipReport {
                source: src.clone(),
                reason: "UNSCANNED: filename does not match calldata-*/eip712-* but the \
                         include-resolved file carries concrete deployments and formats — an \
                         upstream naming change would silently drop trusted rendering. Rename \
                         it or extend the scanner (review 2.3)."
                    .to_string(),
            });
        }
    }
    for src in &sources {
        let resolved = collect_declared_contract_calls(
            src,
            registry_root,
            &mut declared_known_calls,
            &mut declared_contract_signatures,
            &mut source_snapshot,
        )
        .map_err(|e| omission_scan_error(src, input_dir, registry_root, &e))?;
        collect_declared_refusal_only_calls(&resolved, &mut declared_refusal_only_calls)
            .map_err(|e| omission_scan_error(src, input_dir, registry_root, &e))?;
        if resolved_sources.insert(src.clone(), resolved).is_some() {
            return Err(format!(
                "duplicate descriptor source path in catalogue scan: {}",
                review_relative_path(src, input_dir)
            ));
        }
    }
    // Compile only after the omission preflight has inventoried every source.
    // A scoped descriptor must therefore see selector collisions declared by
    // later files, dropped files, and misnamed-but-concrete tripwire files.
    for src in &sources {
        let mut partial_format_drops = Vec::new();
        let resolved = resolved_sources.get(src).ok_or_else(|| {
            format!(
                "internal: no frozen descriptor source for {}",
                src.display()
            )
        })?;
        match compile_resolved_descriptor_with_nested_calldata_enrollments(
            src,
            resolved,
            policy,
            tolerant,
            &mut partial_format_drops,
            erc20_capabilities,
            Some(&declared_contract_signatures),
            nested_calldata_enrollments,
        ) {
            Ok(entries) => {
                // A descriptor can retain safe formats while other source
                // formats fail closed. Preserve every exact overloaded
                // signature and reason in the committed review receipt.
                for reason in partial_format_drops {
                    skips.push(SkipReport {
                        source: src.clone(),
                        reason: format!("PARTIAL FORMAT DROP: {reason}"),
                    });
                }
                for entry in entries {
                    if let Some((selector, markers)) =
                        emitted_refusal_only_collision(&entry, &declared_refusal_only_calls)?
                    {
                        let reason = format!(
                            "authenticated refusalOnlyFormats boundary: emitted selector 0x{} for chain_id={} contract=0x{} collides catalogue-wide with refusal marker(s) {:?}; selector-only runtime dispatch cannot authenticate the competing display",
                            hex::encode(selector),
                            entry.chain_id,
                            hex::encode(entry.contract),
                            markers,
                        );
                        if tolerant {
                            skips.push(SkipReport {
                                source: src.clone(),
                                reason,
                            });
                            continue;
                        }
                        let source = review_relative_path(src, input_dir);
                        return Err(format!("{source}: {reason}"));
                    }
                    emitted.push(entry);
                }
            }
            Err(e) if tolerant => skips.push(SkipReport {
                source: src.clone(),
                reason: e,
            }),
            Err(e) => {
                let source = review_relative_path(src, input_dir);
                let reason = review_stable_reason(&e, registry_root.unwrap_or(input_dir));
                return Err(format!("{source}: {reason}"));
            }
        }
    }

    // ERC-8176 authorizes the exact include-resolved JCS object, not an
    // individual deployment row. Perform this only after the independent
    // known-call scan has inventoried the complete vendored corpus: excluded
    // contract calls must remain Bloom-positive hard refusals.
    if let Some(evidence) = evidence {
        retain_erc8176_threshold_entries(
            &mut emitted,
            policy.min_attesters,
            &evidence.verified,
            skips,
        );
    }

    if emitted.is_empty() {
        return Err("no IR entries emitted (every descriptor rejected by policy)".to_string());
    }

    // 1. Sort by (chain_id, contract, primary_type_hash, context_kind).
    emitted.sort_by(|a, b| {
        (a.chain_id, a.contract, a.primary_type_hash, a.context_kind).cmp(&(
            b.chain_id,
            b.contract,
            b.primary_type_hash,
            b.context_kind,
        ))
    });

    // 2. Handle (chain_id, contract, primary_type_hash, ctx) duplicates.
    //    Byte-identical IRs are benign — the registry legitimately ships the
    //    same token/contract across projects, or a file lists a deployment
    //    twice — so drop the later one (record a skip in tolerant mode).
    //    NON-identical IRs are a trust hazard (review 2.2): the two descriptors
    //    render DIFFERENTLY for the SAME on-chain (chain, contract), and the
    //    survivor was being chosen by lexicographic source-path order — so an
    //    upstream PR adding an alphabetically-earlier file could silently swap
    //    which descriptor the device trusts on the next re-vendor. Refuse in
    //    BOTH modes: force a deliberate human resolution (curate one out) at
    //    build/re-vendor time rather than trusting a filename-order winner. We
    //    vendor the registry, so this fails at re-vendor review, never in prod.
    let mut deduped: Vec<Emitted> = Vec::with_capacity(emitted.len());
    for e in emitted {
        if let Some(prev) = deduped.last() {
            if prev.chain_id == e.chain_id
                && prev.contract == e.contract
                && prev.primary_type_hash == e.primary_type_hash
                && prev.context_kind == e.context_kind
            {
                let key = format!(
                    "chain_id={}, contract=0x{}, primary_type_hash=0x{}, ctx={}",
                    prev.chain_id,
                    hex::encode(prev.contract),
                    hex::encode(prev.primary_type_hash),
                    prev.context_kind,
                );
                if prev.ir_bytes == e.ir_bytes {
                    // Benign byte-identical dup.
                    if tolerant {
                        skips.push(SkipReport {
                            source: e.source.clone(),
                            reason: format!(
                                "duplicate ({key}) byte-identical to {} — deduped",
                                prev.source.display(),
                            ),
                        });
                        continue;
                    }
                    // Strict corpus: even an identical dup is a curation bug.
                    return Err(format!(
                        "duplicate ({key}) — sources: {} vs {}",
                        prev.source.display(),
                        e.source.display(),
                    ));
                }
                return Err(format!(
                    "CONFLICT: non-identical duplicate leaf ({key}) — sources {} vs {} compile \
                     to DIFFERENT IR. The device would trust whichever sorts first by source \
                     path (a silent trust-swap on re-vendor). Resolve by curating one descriptor \
                     out of the vendored tree, or — if both are legitimately needed — ensure they \
                     target distinct deployments.",
                    prev.source.display(),
                    e.source.display(),
                ));
            }
        }
        deduped.push(e);
    }
    let mut emitted = deduped;

    // EIP-712 lookup is bound by (chain, domain separator, FULL primary-type
    // hash), not by the deployment address stored in the catalogue index. A
    // descriptor may contain several formats while `Emitted.primary_type_hash`
    // records only its first one, so the leaf-level duplicate key above cannot
    // detect overlap on a secondary format. Reject every competing accepted
    // mapping before Merkle indexing: otherwise the companion could choose
    // which trusted display the same typed payload receives.
    reject_duplicate_eip712_format_bindings(&emitted)?;

    // 3. Assign leaf indices, compute leaf hashes, build the tree.
    for (i, e) in emitted.iter_mut().enumerate() {
        e.leaf_index = i;
    }
    let leaf_hashes: Vec<[u8; 32]> = emitted.iter().map(|e| leaf_hash(&e.ir_bytes)).collect();
    let tree = MerkleTree::build(leaf_hashes.clone());
    let root = tree.root();
    let proof_depth = tree.depth();

    // 4. Lay out the catalog blob.
    let entry_cnt = emitted.len();
    let entries_size = entry_cnt * ERC7730_DB_ENTRY_LEN;
    let ir_pool_off = ERC7730_DB_HEADER_LEN + entries_size;
    let ir_pool_size: usize = emitted.iter().map(|e| e.ir_bytes.len()).sum();
    let proofs_off = ir_pool_off + ir_pool_size;
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // ── Header (32 B) ────────────────────────────────────────────────
    blob.extend_from_slice(&ERC7730_DB_MAGIC);
    write_u32_le(&mut blob, ERC7730_DB_VERSION);
    write_u32_le(&mut blob, 0); // flags reserved
    write_u32_le(
        &mut blob,
        entry_cnt
            .try_into()
            .map_err(|_| "entry_cnt > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_off
            .try_into()
            .map_err(|_| "ir_pool_off > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_size
            .try_into()
            .map_err(|_| "ir_pool_size > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proof_depth
            .try_into()
            .map_err(|_| "proof_depth > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proofs_off
            .try_into()
            .map_err(|_| "proofs_off > u32::MAX".to_string())?,
    );
    assert_eq!(blob.len(), ERC7730_DB_HEADER_LEN);

    // ── Entries (72 B each) ──────────────────────────────────────────
    let mut current_ir_off = 0u32;
    for e in &emitted {
        let entry_start = blob.len();
        blob.extend_from_slice(&e.chain_id.to_le_bytes()); // 8
        blob.extend_from_slice(&e.contract); // 20
        blob.extend_from_slice(&e.primary_type_hash); // 32
        blob.push(e.context_kind); // 1
        blob.extend_from_slice(&[0u8; 3]); // 3 pad
        write_u32_le(&mut blob, current_ir_off); // 4
        write_u32_le(
            &mut blob,
            e.ir_bytes
                .len()
                .try_into()
                .map_err(|_| "ir_len > u32::MAX".to_string())?,
        ); // 4
        debug_assert_eq!(blob.len() - entry_start, ERC7730_DB_ENTRY_LEN);
        current_ir_off = current_ir_off
            .checked_add(e.ir_bytes.len() as u32)
            .ok_or("ir_off overflow")?;
    }
    assert_eq!(blob.len(), ir_pool_off);

    // ── IR pool ──────────────────────────────────────────────────────
    for e in &emitted {
        blob.extend_from_slice(&e.ir_bytes);
    }
    assert_eq!(blob.len(), proofs_off);

    // ── Proofs ───────────────────────────────────────────────────────
    for i in 0..entry_cnt {
        let proof = tree.proof(i);
        debug_assert_eq!(proof.len(), proof_depth);
        for sib in &proof {
            blob.extend_from_slice(sib);
        }
    }
    assert_eq!(blob.len(), total_size);

    let (
        known_calls_bloom,
        known_call_count,
        known_call_set_hash,
        known_call_set_bits,
        known_calls,
    ) = build_known_calls_bloom(&emitted, &declared_known_calls)?;

    // Derive clear-signing authority from the final P730 bytes, never from the
    // compiler's mutable `emitted` vector. Then take the exact set difference
    // from K and encode only that refused-known remainder as P73K.
    let recovered = recover_clear_contract_calls_from_p730(&blob)?;
    if recovered.root != root || recovered.leaf_count != entry_cnt {
        return Err("final P730 recovery disagrees with the generated root/count".to_string());
    }
    let known_set: BTreeSet<ContractCallTuple> = known_calls.iter().copied().collect();
    let clear_set: BTreeSet<ContractCallTuple> = recovered.calls.iter().copied().collect();
    if let Some((chain_id, contract, selector)) = clear_set.difference(&known_set).next() {
        return Err(format!(
            "clear-capable P730 tuple is absent from K: chain={chain_id} contract=0x{} selector=0x{}",
            hex::encode(contract),
            hex::encode(selector)
        ));
    }
    let forced_eligible_calls: Vec<ContractCallTuple> =
        known_set.difference(&clear_set).copied().collect();
    let forced_eligible_group_count = contract_call_group_count(&forced_eligible_calls);
    let forced_eligible_count = forced_eligible_calls.len();
    let clear_contract_call_count = recovered.calls.len();
    let forced_eligible_set = encode_forced_eligible_set(&forced_eligible_calls)?;
    // Review artifacts are committed and compared across clean worktrees.
    // Never let an absolute checkout prefix become part of their bytes.
    let review_source_root = registry_root.unwrap_or(input_dir);
    let review_text = render_review(
        &emitted,
        skips,
        policy,
        provenance,
        evidence,
        &root,
        known_call_count,
        &known_call_set_hash,
        known_call_set_bits,
        review_source_root,
    );

    let result = Erc7730BuildResult {
        blob,
        root,
        entries: emitted,
        review_text,
        leaf_count: entry_cnt,
        provenance,
        known_calls_bloom,
        known_call_count,
        known_calls,
        known_call_set_hash,
        forced_eligible_set,
        forced_eligible_group_count,
        forced_eligible_count,
        clear_contract_call_count,
        policy_sha256,
    };
    // Re-decode P73K through the shared strict parser and prove the complete
    // partition before any caller can receive a build result.
    prove_forced_eligible_partition(&result)?;
    Ok(result)
}

fn retain_erc8176_threshold_entries(
    emitted: &mut Vec<Emitted>,
    min_attesters: usize,
    verified: &VerifiedAttestationSet,
    skips: &mut Vec<SkipReport>,
) {
    retain_erc8176_threshold_entries_with(
        emitted,
        min_attesters,
        |hash| verified.attester_count(hash),
        skips,
    );
}

fn retain_erc8176_threshold_entries_with(
    emitted: &mut Vec<Emitted>,
    min_attesters: usize,
    mut attester_count: impl FnMut([u8; 32]) -> usize,
    skips: &mut Vec<SkipReport>,
) {
    let mut reported = BTreeSet::<(PathBuf, [u8; 32])>::new();
    emitted.retain(|entry| {
        let count = attester_count(entry.erc8176_hash);
        if count >= min_attesters {
            return true;
        }
        if reported.insert((entry.source.clone(), entry.erc8176_hash)) {
            skips.push(SkipReport {
                source: entry.source.clone(),
                reason: format!(
                    "ERC-8176 attestation threshold: exact resolved descriptor hash 0x{} has {count} distinct eligible trusted attester(s); policy requires {min_attesters} — all leaves from this descriptor were excluded",
                    hex::encode(entry.erc8176_hash),
                ),
            });
        }
        false
    });
}

/// Stabilize fail-closed omission-scan diagnostics for both strict and tolerant
/// catalogue builds. The source is catalogue-relative and any registry-root
/// prefix embedded by include resolution is replaced before it can reach a
/// committed receipt or a path-sensitive test.
fn omission_scan_error(
    source: &Path,
    input_dir: &Path,
    registry_root: Option<&Path>,
    reason: &str,
) -> String {
    let source = review_relative_path(source, input_dir);
    let reason = review_stable_reason(reason, registry_root.unwrap_or(input_dir));
    format!("{source}: known-call omission scan failed closed: {reason}")
}

/// Reject two distinct accepted leaves that can authenticate the same EIP-712
/// payload but carry independently chosen display IR.
///
/// The binding key deliberately uses each parsed format header's full 32-byte
/// type hash. `Emitted.primary_type_hash` is only the first format's catalogue
/// discriminator and would miss a collision on any later format in the leaf.
fn reject_duplicate_eip712_format_bindings(emitted: &[Emitted]) -> Result<(), String> {
    let mut seen: BTreeMap<(u64, [u8; 32], [u8; 32]), &Emitted> = BTreeMap::new();

    for entry in emitted {
        if entry.context_kind != CTX_EIP712 {
            continue;
        }
        let ir = Erc7730Ir::parse(&entry.ir_bytes).map_err(|e| {
            format!(
                "internal: emitted EIP-712 IR from {} failed to parse during duplicate-binding audit: {e:?}",
                entry.source.display()
            )
        })?;
        if ir.chain_id != entry.chain_id {
            return Err(format!(
                "internal: EIP-712 catalogue index/header chain mismatch for {} (index={}, IR={})",
                entry.source.display(),
                entry.chain_id,
                ir.chain_id,
            ));
        }
        for format in ir.format_iter() {
            let format = format.map_err(|e| {
                format!(
                    "internal: emitted EIP-712 format from {} failed to parse during duplicate-binding audit: {e:?}",
                    entry.source.display()
                )
            })?;
            let key = (ir.chain_id, ir.domain_separator, format.type_hash);
            if let Some(previous) = seen.insert(key, entry) {
                return Err(format!(
                    "CONFLICT: duplicate EIP-712 binding chain_id={}, domain_separator=0x{}, type_hash=0x{} across distinct leaves {} (contract=0x{}, descriptor_hash=0x{}) and {} (contract=0x{}, descriptor_hash=0x{}). The companion could choose competing trusted displays for the same typed payload; curate one mapping out.",
                    entry.chain_id,
                    hex::encode(ir.domain_separator),
                    hex::encode(format.type_hash),
                    previous.source.display(),
                    hex::encode(previous.contract),
                    hex::encode(previous.descriptor_hash),
                    entry.source.display(),
                    hex::encode(entry.contract),
                    hex::encode(entry.descriptor_hash),
                ));
            }
        }
    }
    Ok(())
}

type ContractCallKey = ContractCallTuple;
type DeclaredContractSignatures = BTreeMap<ContractCallKey, BTreeSet<String>>;
type DeclaredRefusalOnlyCalls = BTreeMap<ContractCallKey, BTreeSet<String>>;

const MAX_DESCRIPTOR_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_DESCRIPTOR_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_DESCRIPTOR_SNAPSHOT_FILES: usize = 4096;

/// Immutable, bounded view of every descriptor/include file consumed by one
/// catalogue build.
///
/// Omission inventory and compilation must never reopen the source tree
/// independently: otherwise a concurrent replacement can make the compiled
/// descriptor differ from the calls entered into the hard-refusal Bloom. The
/// first successful regular-file read wins for the whole build; every later
/// consumer receives a clone of the same parsed bytes.
#[derive(Default)]
struct DescriptorSourceSnapshot {
    json_by_path: BTreeMap<PathBuf, serde_json::Value>,
    total_bytes: usize,
}

impl DescriptorSourceSnapshot {
    fn load_json(&mut self, path: &Path) -> Result<serde_json::Value, String> {
        let before = fs::symlink_metadata(path)
            .map_err(|e| format!("inspect descriptor source {}: {e}", path.display()))?;
        if before.file_type().is_symlink() || !before.file_type().is_file() {
            return Err(format!(
                "descriptor source {} must be a non-symlink regular file",
                path.display()
            ));
        }
        if before.len() > MAX_DESCRIPTOR_SOURCE_BYTES {
            return Err(format!(
                "descriptor source {} is {} bytes; per-file cap is {MAX_DESCRIPTOR_SOURCE_BYTES}",
                path.display(),
                before.len()
            ));
        }

        let canonical = path
            .canonicalize()
            .map_err(|e| format!("canonicalize descriptor source {}: {e}", path.display()))?;
        if let Some(json) = self.json_by_path.get(&canonical) {
            return Ok(json.clone());
        }
        if self.json_by_path.len() >= MAX_DESCRIPTOR_SNAPSHOT_FILES {
            return Err(format!(
                "descriptor source snapshot exceeds {MAX_DESCRIPTOR_SNAPSHOT_FILES} distinct files"
            ));
        }

        let file = File::open(path)
            .map_err(|e| format!("open descriptor source {}: {e}", path.display()))?;
        let after = file
            .metadata()
            .map_err(|e| format!("fstat descriptor source {}: {e}", path.display()))?;
        if !after.file_type().is_file() {
            return Err(format!(
                "descriptor source {} changed to a non-regular file",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(format!(
                    "descriptor source {} changed between stat and open",
                    path.display()
                ));
            }
        }

        let initial_capacity = usize::try_from(after.len())
            .unwrap_or(usize::MAX)
            .min(MAX_DESCRIPTOR_SOURCE_BYTES as usize);
        let mut raw = Vec::with_capacity(initial_capacity);
        file.take(MAX_DESCRIPTOR_SOURCE_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|e| format!("read descriptor source {}: {e}", path.display()))?;
        if raw.len() as u64 > MAX_DESCRIPTOR_SOURCE_BYTES {
            return Err(format!(
                "descriptor source {} grew beyond {MAX_DESCRIPTOR_SOURCE_BYTES} bytes",
                path.display()
            ));
        }
        let total_bytes = self
            .total_bytes
            .checked_add(raw.len())
            .ok_or_else(|| "descriptor source snapshot byte count overflow".to_string())?;
        if total_bytes > MAX_DESCRIPTOR_SNAPSHOT_BYTES {
            return Err(format!(
                "descriptor source snapshot is {total_bytes} bytes; aggregate cap is {MAX_DESCRIPTOR_SNAPSHOT_BYTES}"
            ));
        }
        let json = parse_json_value_rejecting_duplicate_keys(&raw)
            .map_err(|e| format!("parse descriptor source {}: {e}", path.display()))?;
        self.total_bytes = total_bytes;
        self.json_by_path.insert(canonical, json.clone());
        Ok(json)
    }
}

fn collect_declared_contract_calls(
    path: &Path,
    registry_root: Option<&Path>,
    out: &mut BTreeSet<ContractCallKey>,
    signatures: &mut DeclaredContractSignatures,
    snapshot: &mut DescriptorSourceSnapshot,
) -> Result<serde_json::Value, String> {
    // Scan the raw descriptor first so local declarations remain visible even
    // when an include contributes a different half of the tuple. The resolved
    // scan below is nevertheless mandatory: an include may supply additional
    // deployments or every format, so any read/parse/resolution failure makes
    // the complete known-call set unknowable and must abort the catalogue.
    // Unioning both successful views is conservative; surplus tuples are safe
    // Bloom false positives, whereas dropping either view could be a false
    // negative.
    let raw_json = snapshot.load_json(path)?;
    collect_contract_calls_from_json(&raw_json, out, signatures)?;

    let json = load_resolved_descriptor_json_from_snapshot(path, registry_root, snapshot)?;
    collect_contract_calls_from_json(&json, out, signatures)?;
    Ok(json)
}

fn collect_contract_calls_from_json(
    json: &serde_json::Value,
    out: &mut BTreeSet<ContractCallKey>,
    signatures: &mut DeclaredContractSignatures,
) -> Result<(), String> {
    let Some(deployments_value) = json.pointer("/context/contract/deployments") else {
        return Ok(()); // EIP-712 descriptor or an include-only template.
    };
    let deployments = deployments_value
        .as_array()
        .ok_or_else(|| "context.contract.deployments is not an array".to_string())?;
    let Some(formats_value) = json.pointer("/display/formats") else {
        return Ok(()); // A raw split descriptor may receive formats from an include.
    };
    let formats = formats_value
        .as_object()
        .ok_or_else(|| "display.formats is not an object".to_string())?;

    let mut selectors = BTreeMap::<[u8; 4], BTreeSet<String>>::new();
    for signature in formats.keys() {
        // Selector derivation is deliberately less permissive than blind
        // omission but independent of WYSIWYS name validation. Duplicate
        // parameter names make a format unrenderable while its ABI selector is
        // still determined entirely by the types; it must remain known.
        let canonical = contract_selector_signature(signature)?;
        let digest = keccak256(canonical.as_bytes());
        selectors
            .entry([digest[0], digest[1], digest[2], digest[3]])
            .or_default()
            .insert(canonical);
    }

    for (index, deployment) in deployments.iter().enumerate() {
        let chain_id = deployment
            .get("chainId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("contract deployment[{index}] has no u64 chainId"))?;
        let address = deployment
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("contract deployment[{index}] has no string address"))?;
        let contract = parse_address(address)
            .map_err(|e| format!("contract deployment[{index}] address: {e}"))?;
        for (selector, canonical_signatures) in &selectors {
            let key = (chain_id, contract, *selector);
            out.insert(key);
            signatures
                .entry(key)
                .or_default()
                .extend(canonical_signatures.iter().cloned());
        }
    }
    Ok(())
}

/// Inventory every structurally declared refusal marker before compilation.
///
/// For contract contexts, `refusalOnlyFormats` is authored as a
/// source-signature list while the EVM and device dispatch by four-byte
/// selector. Keeping this catalogue-wide selector inventory prevents a
/// colliding sibling signature from restoring clear-signing authority that
/// another authenticated descriptor explicitly removed. EIP-712 markers skip
/// this inventory and are validated later against exact full type signatures.
fn collect_declared_refusal_only_calls(
    json: &serde_json::Value,
    out: &mut DeclaredRefusalOnlyCalls,
) -> Result<(), String> {
    let Some(markers_value) = json.pointer("/_pqsigner/refusalOnlyFormats") else {
        return Ok(());
    };
    let markers = markers_value
        .as_array()
        .ok_or_else(|| "_pqsigner.refusalOnlyFormats is not an array".to_string())?;
    if markers.is_empty() {
        return Ok(());
    }

    let deployments = match json.pointer("/context/contract/deployments") {
        Some(value) => value.as_array().ok_or_else(|| {
            "_pqsigner.refusalOnlyFormats is contract-context only and requires contract deployments"
                .to_string()
        })?,
        None if json.pointer("/context/contract").is_some() => {
            return Err(
                "_pqsigner.refusalOnlyFormats is contract-context only and requires contract deployments"
                    .to_string(),
            );
        }
        None if json.pointer("/context/eip712").is_some() => {
            // Typed-data dispatch authenticates the full 32-byte type hash.
            // There is no four-byte known-call selector inventory to augment
            // or collision boundary to enforce here; compile-time validation
            // below checks the exact displayed type-signature strings.
            return Ok(());
        }
        None => {
            return Err(
                "_pqsigner.refusalOnlyFormats is contract-context only and requires contract deployments"
                    .to_string(),
            );
        }
    };
    let formats = json
        .pointer("/display/formats")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            "_pqsigner.refusalOnlyFormats requires a concrete display.formats object".to_string()
        })?;

    let mut selectors = Vec::with_capacity(markers.len());
    for (index, marker) in markers.iter().enumerate() {
        let signature = marker
            .as_str()
            .ok_or_else(|| format!("_pqsigner.refusalOnlyFormats[{index}] is not a string"))?;
        if !formats.contains_key(signature) {
            return Err(format!(
                "_pqsigner.refusalOnlyFormats[{index}] names unknown format `{signature}`"
            ));
        }
        let canonical = contract_selector_signature(signature).map_err(|error| {
            format!("_pqsigner.refusalOnlyFormats[{index}] cannot be selector-bound: {error}")
        })?;
        let digest = keccak256(canonical.as_bytes());
        selectors.push(([digest[0], digest[1], digest[2], digest[3]], canonical));
    }

    for (index, deployment) in deployments.iter().enumerate() {
        let chain_id = deployment
            .get("chainId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                format!(
                    "context.contract.deployments[{index}].chainId is missing or not a u64 while inventorying refusalOnlyFormats"
                )
            })?;
        let address_text = deployment
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "context.contract.deployments[{index}].address is missing or not a string while inventorying refusalOnlyFormats"
                )
            })?;
        let address = parse_address(address_text).map_err(|error| {
            format!(
                "context.contract.deployments[{index}].address is invalid while inventorying refusalOnlyFormats: {error}"
            )
        })?;
        for (selector, canonical) in &selectors {
            out.entry((chain_id, address, *selector))
                .or_default()
                .insert(canonical.clone());
        }
    }
    Ok(())
}

fn emitted_refusal_only_collision(
    entry: &Emitted,
    refusal_only_calls: &DeclaredRefusalOnlyCalls,
) -> Result<Option<([u8; 4], Vec<String>)>, String> {
    if entry.context_kind != CTX_CONTRACT {
        return Ok(None);
    }
    let ir = Erc7730Ir::parse(&entry.ir_bytes).map_err(|error| {
        format!(
            "internal: inspect emitted refusal boundary for {}: {error:?}",
            entry.source.display()
        )
    })?;
    for format in ir.format_iter() {
        let format = format.map_err(|error| {
            format!(
                "internal: inspect emitted refusal format for {}: {error:?}",
                entry.source.display()
            )
        })?;
        if let Some(markers) =
            refusal_only_calls.get(&(entry.chain_id, entry.contract, format.selector))
        {
            return Ok(Some((
                format.selector,
                markers.iter().cloned().collect::<Vec<_>>(),
            )));
        }
    }
    Ok(None)
}

/// Whether an unselected, include-resolved JSON file is a concrete descriptor
/// rather than an incomplete reusable template. This affects the visible skip
/// receipt only; every unselected JSON is omission-scanned regardless.
fn has_concrete_descriptor_shape(json: &serde_json::Value) -> bool {
    let has_formats = json
        .pointer("/display/formats")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|formats| !formats.is_empty());
    let has_deployments = [
        "/context/contract/deployments",
        "/context/eip712/deployments",
    ]
    .iter()
    .any(|pointer| {
        json.pointer(pointer)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|deployments| !deployments.is_empty())
    });
    has_formats && has_deployments
}

/// Derive the canonical Solidity selector signature without relaxing the
/// renderer's duplicate-name rejection. A duplicate parameter name is invalid
/// trusted-display metadata but does not change the ABI type list or selector.
fn contract_selector_signature(signature: &str) -> Result<String, String> {
    let signature = signature.trim();
    if signature.starts_with("0x") {
        return Err(format!(
            "contract format key `{signature}` is a selector-only hex key; the generator cannot authenticate its canonical ABI types, so omission protection fails closed"
        ));
    }
    if !signature.is_ascii() {
        return Err(format!(
            "contract format `{signature}` contains non-ASCII Solidity syntax"
        ));
    }

    let mut parser = SelectorSignatureParser::new(signature);
    parser.skip_ws();
    let function_name = parser.parse_identifier("function name")?;
    parser.skip_ws();
    let args = parser.parse_parameter_list()?;
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(format!(
            "contract format `{signature}` has trailing syntax after its argument list"
        ));
    }
    Ok(format!("{function_name}{args}"))
}

/// Selector-only parser kept independent of renderer name/path policy.
///
/// ERC-7730 format keys carry Solidity-like parameter declarations, whereas an
/// EVM selector hashes the canonical ABI type list. This parser deliberately
/// accepts renderer-dead but selector-valid shapes (unnamed/duplicate names,
/// nested tuple arrays), while rejecting anything whose canonical type cannot
/// be derived with confidence. That asymmetry is safe for the omission Bloom:
/// surplus known tuples are refusals; a silently omitted tuple is a blind-sign
/// escape.
struct SelectorSignatureParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SelectorSignatureParser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.input.len()
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.pos += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> Result<(), String> {
        if self.peek() != Some(expected) {
            return Err(format!(
                "expected `{}` at byte {} in contract format `{}`",
                char::from(expected),
                self.pos,
                self.input
            ));
        }
        self.pos += 1;
        Ok(())
    }

    fn parse_identifier(&mut self, what: &str) -> Result<&'a str, String> {
        let start = self.pos;
        let Some(first) = self.peek() else {
            return Err(format!(
                "missing {what} in contract format `{}`",
                self.input
            ));
        };
        if !(first.is_ascii_alphabetic() || matches!(first, b'_' | b'$')) {
            return Err(format!(
                "invalid {what} at byte {} in contract format `{}`",
                self.pos, self.input
            ));
        }
        self.pos += 1;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        {
            self.pos += 1;
        }
        Ok(&self.input[start..self.pos])
    }

    fn parse_parameter_list(&mut self) -> Result<String, String> {
        self.consume(b'(')?;
        self.skip_ws();
        let mut canonical = String::from("(");
        if self.peek() == Some(b')') {
            self.pos += 1;
            canonical.push(')');
            return Ok(canonical);
        }

        let mut first = true;
        loop {
            if !first {
                canonical.push(',');
            }
            canonical.push_str(&self.parse_parameter()?);
            first = false;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                    if matches!(self.peek(), Some(b',' | b')') | None) {
                        return Err(format!(
                            "empty parameter in contract format `{}`",
                            self.input
                        ));
                    }
                }
                Some(b')') => {
                    self.pos += 1;
                    canonical.push(')');
                    return Ok(canonical);
                }
                _ => {
                    return Err(format!(
                        "expected `,` or `)` at byte {} in contract format `{}`",
                        self.pos, self.input
                    ));
                }
            }
        }
    }

    fn parse_parameter(&mut self) -> Result<String, String> {
        self.skip_ws();
        let canonical = self.parse_type()?;
        self.skip_ws();

        // Names and data-location/payability modifiers do not participate in
        // selector hashing. Accept them only as complete Solidity identifiers;
        // a second unrecognised identifier is ambiguous and fails closed.
        let mut saw_name = false;
        while !matches!(self.peek(), Some(b',' | b')') | None) {
            let token = self.parse_identifier("parameter name or modifier")?;
            if matches!(token, "memory" | "calldata" | "storage" | "payable") {
                // Modifier placement/type legality is renderer/compiler policy;
                // ignoring a syntactically clear modifier can only add a safe
                // Bloom false positive.
            } else if !saw_name {
                saw_name = true;
            } else {
                return Err(format!(
                    "ambiguous trailing parameter syntax in contract format `{}`",
                    self.input
                ));
            }
            self.skip_ws();
        }
        Ok(canonical)
    }

    fn parse_type(&mut self) -> Result<String, String> {
        self.skip_ws();
        let mut canonical = if self.peek() == Some(b'(') {
            self.parse_parameter_list()?
        } else {
            let source_type = self.parse_identifier("ABI type")?;
            if source_type == "tuple" {
                self.skip_ws();
                if self.peek() != Some(b'(') {
                    return Err(format!(
                        "bare `tuple` has no canonical ABI members in contract format `{}`",
                        self.input
                    ));
                }
                self.parse_parameter_list()?
            } else {
                canonical_contract_elementary_type(source_type, self.input)?.to_string()
            }
        };

        loop {
            self.skip_ws();
            if self.peek() != Some(b'[') {
                break;
            }
            self.pos += 1;
            self.skip_ws();
            let length_start = self.pos;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.pos += 1;
            }
            let length = &self.input[length_start..self.pos];
            self.skip_ws();
            self.consume(b']')?;
            if !length.is_empty()
                && ((length.len() > 1 && length.starts_with('0'))
                    || length
                        .parse::<u32>()
                        .ok()
                        .filter(|value| *value > 0)
                        .is_none())
            {
                return Err(format!(
                    "contract format `{}` has noncanonical fixed-array length `{length}`",
                    self.input
                ));
            }
            canonical.push('[');
            canonical.push_str(length);
            canonical.push(']');
        }
        Ok(canonical)
    }
}

fn canonical_contract_elementary_type<'a>(ty: &'a str, original: &str) -> Result<&'a str, String> {
    let canonical = match ty {
        "uint" => "uint256",
        "int" => "int256",
        "byte" => "bytes1",
        "fixed" => "fixed128x18",
        "ufixed" => "ufixed128x18",
        "address" | "bool" | "string" | "bytes" | "function" => ty,
        _ if canonical_int_type(ty, "uint")
            || canonical_int_type(ty, "int")
            || canonical_bytes_type(ty)
            || canonical_fixed_type(ty, "fixed")
            || canonical_fixed_type(ty, "ufixed") =>
        {
            ty
        }
        _ => {
            return Err(format!(
                "contract format `{original}` has unsupported ABI type `{ty}`"
            ));
        }
    };
    Ok(canonical)
}

fn canonical_int_type(ty: &str, prefix: &str) -> bool {
    let Some(width) = ty.strip_prefix(prefix) else {
        return false;
    };
    !width.is_empty()
        && !(width.len() > 1 && width.starts_with('0'))
        && matches!(width.parse::<u16>(), Ok(bits) if (8..=256).contains(&bits) && bits % 8 == 0)
}

fn canonical_bytes_type(ty: &str) -> bool {
    let Some(width) = ty.strip_prefix("bytes") else {
        return false;
    };
    !width.is_empty()
        && !(width.len() > 1 && width.starts_with('0'))
        && matches!(width.parse::<u8>(), Ok(bytes) if (1..=32).contains(&bytes))
}

fn canonical_fixed_type(ty: &str, prefix: &str) -> bool {
    let Some(rest) = ty.strip_prefix(prefix) else {
        return false;
    };
    let Some((m, n)) = rest.split_once('x') else {
        return false;
    };
    !(m.len() > 1 && m.starts_with('0'))
        && !(n.len() > 1 && n.starts_with('0'))
        && matches!(m.parse::<u16>(), Ok(bits) if (8..=256).contains(&bits) && bits % 8 == 0)
        && matches!(n.parse::<u8>(), Ok(decimals) if (1..=80).contains(&decimals))
}

fn build_known_calls_bloom(
    entries: &[Emitted],
    declared: &BTreeSet<(u64, [u8; 20], [u8; 4])>,
) -> Result<
    (
        [u8; BLOOM_BYTES],
        usize,
        [u8; 32],
        usize,
        Vec<(u64, [u8; 20], [u8; 4])>,
    ),
    String,
> {
    let mut tuples = declared.clone();
    for entry in entries {
        if entry.context_kind != CTX_CONTRACT {
            continue;
        }
        let ir = Erc7730Ir::parse(&entry.ir_bytes).map_err(|e| {
            format!(
                "known-call filter parse failed for {}: {e:?}",
                entry.source.display()
            )
        })?;
        for format in ir.format_iter() {
            let format = format.map_err(|e| {
                format!(
                    "known-call filter format failed for {}: {e:?}",
                    entry.source.display()
                )
            })?;
            tuples.insert((entry.chain_id, entry.contract, format.selector));
        }
    }

    let mut bloom = [0u8; BLOOM_BYTES];
    for (chain_id, contract, selector) in &tuples {
        insert_known_call(&mut bloom, *chain_id, contract, selector);
    }
    let set_hash = known_call_set_hash(&tuples)?;
    let set_bits = enforce_known_call_bloom_occupancy(&bloom)?;
    let exact = tuples.iter().copied().collect();
    Ok((bloom, tuples.len(), set_hash, set_bits, exact))
}

/// Keep the omission filter's safe-refusal rate governed as the registry
/// grows. With seven probes, a 25%-full filter has an estimated random false
/// positive rate of `(1/4)^7 = 1/16384`, below the documented 1/10000 ceiling.
fn enforce_known_call_bloom_occupancy(bloom: &[u8; BLOOM_BYTES]) -> Result<usize, String> {
    const BLOOM_BITS: usize = BLOOM_BYTES * 8;
    const MAX_SET_BITS: usize = BLOOM_BITS / 4;
    let set_bits: usize = bloom.iter().map(|byte| byte.count_ones() as usize).sum();
    if set_bits > MAX_SET_BITS {
        return Err(format!(
            "known-call Bloom filter is saturated ({set_bits}/{BLOOM_BITS} bits set, cap {MAX_SET_BITS}); increase or shard it before accepting registry growth so false-positive refusals remain below 1/10000"
        ));
    }
    Ok(set_bits)
}

/// Hash the exact canonical known-call tuple set used to build the omission
/// filter.  The fixed-width encoding is unambiguous and the `BTreeSet` order
/// makes the receipt independent of registry traversal or host filesystem
/// ordering.
fn known_call_set_hash(tuples: &BTreeSet<(u64, [u8; 20], [u8; 4])>) -> Result<[u8; 32], String> {
    let count = u64::try_from(tuples.len())
        .map_err(|_| "known-call tuple count does not fit u64".to_string())?;
    let mut h = Sha256::new();
    h.update(b"pqsigner/erc7730-known-call-set-v1");
    h.update(count.to_be_bytes());
    for (chain_id, contract, selector) in tuples {
        h.update(chain_id.to_be_bytes());
        h.update(contract);
        h.update(selector);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// Strictly recovered clear-capable contract-call inventory from one final
/// `P730` byte image. The root and leaf count are reconstructed from the same
/// parsed IR slices so callers can bind the result back to their build result
/// without consulting the compiler's in-memory [`Emitted`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P730ContractInventory {
    pub calls: Vec<ContractCallTuple>,
    pub root: [u8; 32],
    pub leaf_count: usize,
}

/// Strictly parse a complete `P730` catalogue and recover `C`, the exact set
/// of accepted contract-context `(chain, target, selector)` tuples.
///
/// This deliberately starts from the final serialized bytes. It validates the
/// complete header, canonical entry layout/order, contiguous IR pool, every IR
/// with the on-device deep parser, the index/IR bindings, the Merkle tree and
/// every stored proof. It rejects trailing data and returns a sorted unique
/// tuple vector.
pub fn recover_clear_contract_calls_from_p730(
    blob: &[u8],
) -> Result<P730ContractInventory, String> {
    if blob.len() < ERC7730_DB_HEADER_LEN {
        return Err(format!(
            "P730 catalogue is too short: {} < {}",
            blob.len(),
            ERC7730_DB_HEADER_LEN
        ));
    }
    if blob[..4] != ERC7730_DB_MAGIC {
        return Err("P730 catalogue has bad magic".to_string());
    }
    let version = read_p730_u32_le(blob, 4, "version")?;
    if version != ERC7730_DB_VERSION {
        return Err(format!(
            "P730 catalogue version {version} != {ERC7730_DB_VERSION}"
        ));
    }
    let flags = read_p730_u32_le(blob, 8, "flags")?;
    if flags != 0 {
        return Err(format!(
            "P730 catalogue reserved flags are non-zero: {flags}"
        ));
    }

    let entry_count_u32 = read_p730_u32_le(blob, 12, "entry count")?;
    if entry_count_u32 == 0 {
        return Err("P730 catalogue has no entries".to_string());
    }
    let entry_count = usize::try_from(entry_count_u32)
        .map_err(|_| "P730 entry count does not fit usize".to_string())?;
    let entries_size = entry_count
        .checked_mul(ERC7730_DB_ENTRY_LEN)
        .ok_or_else(|| "P730 entry-table size overflow".to_string())?;
    let expected_pool_off = ERC7730_DB_HEADER_LEN
        .checked_add(entries_size)
        .ok_or_else(|| "P730 entry-table end overflow".to_string())?;
    let ir_pool_off = usize::try_from(read_p730_u32_le(blob, 16, "IR pool offset")?)
        .map_err(|_| "P730 IR pool offset does not fit usize".to_string())?;
    if ir_pool_off != expected_pool_off || ir_pool_off > blob.len() {
        return Err(format!(
            "P730 non-canonical IR pool offset: {ir_pool_off} != {expected_pool_off}"
        ));
    }
    let ir_pool_size = usize::try_from(read_p730_u32_le(blob, 20, "IR pool size")?)
        .map_err(|_| "P730 IR pool size does not fit usize".to_string())?;
    let ir_pool_end = ir_pool_off
        .checked_add(ir_pool_size)
        .ok_or_else(|| "P730 IR pool end overflow".to_string())?;
    if ir_pool_end > blob.len() {
        return Err("P730 IR pool exceeds catalogue bounds".to_string());
    }
    let proof_depth = usize::try_from(read_p730_u32_le(blob, 24, "proof depth")?)
        .map_err(|_| "P730 proof depth does not fit usize".to_string())?;
    if proof_depth > MAX_PROOF_DEPTH {
        return Err(format!(
            "P730 proof depth {proof_depth} exceeds cap {MAX_PROOF_DEPTH}"
        ));
    }
    let expected_depth = if entry_count_u32 == 1 {
        0
    } else {
        (u32::BITS - (entry_count_u32 - 1).leading_zeros()) as usize
    };
    if proof_depth != expected_depth {
        return Err(format!(
            "P730 non-canonical proof depth: {proof_depth} != {expected_depth}"
        ));
    }
    let proofs_off = usize::try_from(read_p730_u32_le(blob, 28, "proofs offset")?)
        .map_err(|_| "P730 proofs offset does not fit usize".to_string())?;
    if proofs_off != ir_pool_end {
        return Err(format!(
            "P730 non-canonical proofs offset: {proofs_off} != {ir_pool_end}"
        ));
    }
    let proof_size = proof_depth
        .checked_mul(32)
        .ok_or_else(|| "P730 proof size overflow".to_string())?;
    let proofs_size = entry_count
        .checked_mul(proof_size)
        .ok_or_else(|| "P730 proof region size overflow".to_string())?;
    let expected_end = proofs_off
        .checked_add(proofs_size)
        .ok_or_else(|| "P730 catalogue size overflow".to_string())?;
    if expected_end != blob.len() {
        return Err(format!(
            "P730 proof region/trailing bytes mismatch: {expected_end} != {}",
            blob.len()
        ));
    }

    let mut calls = BTreeSet::<ContractCallTuple>::new();
    let mut irs = Vec::<&[u8]>::with_capacity(entry_count);
    let mut previous_key: Option<(u64, [u8; 20], [u8; 32], u8)> = None;
    let mut next_ir_off = 0usize;
    for index in 0..entry_count {
        let base = ERC7730_DB_HEADER_LEN
            .checked_add(
                index
                    .checked_mul(ERC7730_DB_ENTRY_LEN)
                    .ok_or_else(|| "P730 entry offset overflow".to_string())?,
            )
            .ok_or_else(|| "P730 entry offset overflow".to_string())?;
        let entry = blob
            .get(base..base + ERC7730_DB_ENTRY_LEN)
            .ok_or_else(|| format!("P730 entry {index} is truncated"))?;
        let chain_id = u64::from_le_bytes(
            entry[0..8]
                .try_into()
                .map_err(|_| format!("P730 entry {index} chain is truncated"))?,
        );
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&entry[8..28]);
        let mut primary_type_hash = [0u8; 32];
        primary_type_hash.copy_from_slice(&entry[28..60]);
        let context_kind = entry[60];
        if !matches!(context_kind, CTX_CONTRACT | CTX_EIP712) {
            return Err(format!(
                "P730 entry {index} has invalid context kind {context_kind}"
            ));
        }
        if entry[61..64] != [0u8; 3] {
            return Err(format!("P730 entry {index} reserved padding is non-zero"));
        }
        let ir_off = usize::try_from(u32::from_le_bytes(
            entry[64..68]
                .try_into()
                .map_err(|_| format!("P730 entry {index} IR offset is truncated"))?,
        ))
        .map_err(|_| format!("P730 entry {index} IR offset does not fit usize"))?;
        let ir_len = usize::try_from(u32::from_le_bytes(
            entry[68..72]
                .try_into()
                .map_err(|_| format!("P730 entry {index} IR length is truncated"))?,
        ))
        .map_err(|_| format!("P730 entry {index} IR length does not fit usize"))?;
        if ir_len == 0 || ir_len > MAX_IR_LEN {
            return Err(format!(
                "P730 entry {index} IR length {ir_len} is outside 1..={MAX_IR_LEN}"
            ));
        }
        if ir_off != next_ir_off {
            return Err(format!(
                "P730 entry {index} non-contiguous IR offset: {ir_off} != {next_ir_off}"
            ));
        }
        let ir_end = ir_off
            .checked_add(ir_len)
            .ok_or_else(|| format!("P730 entry {index} IR end overflow"))?;
        if ir_end > ir_pool_size {
            return Err(format!("P730 entry {index} IR exceeds the declared pool"));
        }
        next_ir_off = ir_end;

        let key = (chain_id, contract, primary_type_hash, context_kind);
        if previous_key
            .as_ref()
            .is_some_and(|previous| key <= *previous)
        {
            return Err(format!(
                "P730 entry {index} sort key is duplicate or out of order"
            ));
        }
        previous_key = Some(key);

        let ir_start = ir_pool_off
            .checked_add(ir_off)
            .ok_or_else(|| format!("P730 entry {index} absolute IR offset overflow"))?;
        let ir_end_absolute = ir_start
            .checked_add(ir_len)
            .ok_or_else(|| format!("P730 entry {index} absolute IR end overflow"))?;
        let ir_bytes = blob
            .get(ir_start..ir_end_absolute)
            .ok_or_else(|| format!("P730 entry {index} IR is truncated"))?;
        let ir = Erc7730Ir::parse(ir_bytes)
            .map_err(|error| format!("P730 entry {index} IR is invalid: {error:?}"))?;
        let expected_context = if context_kind == CTX_CONTRACT {
            ContextKind::Contract
        } else {
            ContextKind::Eip712
        };
        if ir.chain_id != chain_id || ir.contract != contract || ir.context_kind != expected_context
        {
            return Err(format!(
                "P730 entry {index} index fields disagree with authenticated IR"
            ));
        }
        let format_count = ir
            .format_count()
            .map_err(|error| format!("P730 entry {index} format count is invalid: {error:?}"))?;
        if format_count == 0 {
            return Err(format!(
                "P730 entry {index} has no selector-bearing formats"
            ));
        }
        let expected_primary_type_hash = if context_kind == CTX_CONTRACT {
            [0u8; 32]
        } else {
            ir.format_iter()
                .next()
                .ok_or_else(|| format!("P730 entry {index} EIP-712 IR has no formats"))?
                .map_err(|error| {
                    format!("P730 entry {index} first EIP-712 format is invalid: {error:?}")
                })?
                .type_hash
        };
        if primary_type_hash != expected_primary_type_hash {
            return Err(format!(
                "P730 entry {index} primary-type index disagrees with authenticated IR"
            ));
        }

        if context_kind == CTX_CONTRACT {
            for format in ir.format_iter() {
                let format = format.map_err(|error| {
                    format!("P730 entry {index} contract format is invalid: {error:?}")
                })?;
                if !calls.insert((chain_id, contract, format.selector)) {
                    return Err(format!(
                        "P730 entry {index} duplicates clear tuple chain={chain_id} contract=0x{} selector=0x{}",
                        hex::encode(contract),
                        hex::encode(format.selector)
                    ));
                }
            }
        }
        irs.push(ir_bytes);
    }
    if next_ir_off != ir_pool_size {
        return Err(format!(
            "P730 IR slices do not consume pool: {next_ir_off} != {ir_pool_size}"
        ));
    }

    let tree = MerkleTree::build(irs.iter().map(|ir| leaf_hash(ir)).collect());
    if tree.depth() != proof_depth {
        return Err(format!(
            "P730 reconstructed proof depth {} != {proof_depth}",
            tree.depth()
        ));
    }
    for index in 0..entry_count {
        let stored_start = proofs_off
            .checked_add(
                index
                    .checked_mul(proof_size)
                    .ok_or_else(|| "P730 stored proof offset overflow".to_string())?,
            )
            .ok_or_else(|| "P730 stored proof offset overflow".to_string())?;
        let stored = blob
            .get(stored_start..stored_start + proof_size)
            .ok_or_else(|| format!("P730 proof {index} is truncated"))?;
        let expected = tree.proof(index);
        if expected
            .iter()
            .zip(stored.chunks_exact(32))
            .any(|(node, chunk)| node.as_slice() != chunk)
        {
            return Err(format!("P730 stored proof {index} disagrees with IR tree"));
        }
    }

    Ok(P730ContractInventory {
        calls: calls.into_iter().collect(),
        root: tree.root(),
        leaf_count: entry_count,
    })
}

fn read_p730_u32_le(blob: &[u8], offset: usize, field: &str) -> Result<u32, String> {
    let bytes = blob
        .get(offset..offset + 4)
        .ok_or_else(|| format!("P730 {field} is truncated"))?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| format!("P730 {field} is truncated"))?,
    ))
}

/// Encode a sorted unique forced-eligible tuple vector as canonical `P73K`.
/// Callers normally use [`Erc7730BuildResult::forced_eligible_set`]; this
/// public primitive exists for the independent release-path implementation and
/// focused format tests.
pub fn encode_forced_eligible_set(calls: &[ContractCallTuple]) -> Result<Vec<u8>, String> {
    if calls.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("P73K input tuples are duplicate or not strictly sorted".to_string());
    }

    let tuple_count =
        u32::try_from(calls.len()).map_err(|_| "P73K tuple count exceeds u32".to_string())?;
    let mut groups = Vec::<(u64, [u8; 20], u32, u16)>::new();
    let mut cursor = 0usize;
    while cursor < calls.len() {
        let (chain_id, contract, _) = calls[cursor];
        let start = cursor;
        while cursor < calls.len() && calls[cursor].0 == chain_id && calls[cursor].1 == contract {
            cursor += 1;
        }
        let selector_count = u16::try_from(cursor - start)
            .map_err(|_| "P73K group selector count exceeds u16".to_string())?;
        let selector_start =
            u32::try_from(start).map_err(|_| "P73K selector start exceeds u32".to_string())?;
        groups.push((chain_id, contract, selector_start, selector_count));
    }
    let group_count =
        u32::try_from(groups.len()).map_err(|_| "P73K group count exceeds u32".to_string())?;
    let expected_len = FORCED_ELIGIBLE_HEADER_LEN
        .checked_add(
            groups
                .len()
                .checked_mul(FORCED_ELIGIBLE_GROUP_LEN)
                .ok_or_else(|| "P73K group-table size overflow".to_string())?,
        )
        .and_then(|length| {
            length.checked_add(calls.len().checked_mul(FORCED_ELIGIBLE_SELECTOR_LEN)?)
        })
        .ok_or_else(|| "P73K total size overflow".to_string())?;
    let mut out = Vec::with_capacity(expected_len);
    out.extend_from_slice(&FORCED_ELIGIBLE_MAGIC);
    out.extend_from_slice(&FORCED_ELIGIBLE_SCHEMA_V1.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(FORCED_ELIGIBLE_HEADER_LEN)
            .map_err(|_| "P73K header length exceeds u16".to_string())?
            .to_be_bytes(),
    );
    out.extend_from_slice(&group_count.to_be_bytes());
    out.extend_from_slice(&tuple_count.to_be_bytes());
    for (chain_id, contract, selector_start, selector_count) in groups {
        out.extend_from_slice(&chain_id.to_be_bytes());
        out.extend_from_slice(&contract);
        out.extend_from_slice(&selector_start.to_be_bytes());
        out.extend_from_slice(&selector_count.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    for (_, _, selector) in calls {
        out.extend_from_slice(selector);
    }
    if out.len() != expected_len {
        return Err(format!(
            "internal P73K encoded length {} != {expected_len}",
            out.len()
        ));
    }
    Ok(out)
}

fn contract_call_group_count(calls: &[ContractCallTuple]) -> usize {
    calls
        .iter()
        .enumerate()
        .filter(|(index, tuple)| {
            *index == 0 || calls[*index - 1].0 != tuple.0 || calls[*index - 1].1 != tuple.1
        })
        .count()
}

/// Re-run the complete `K = C disjoint-union F` construction proof from the
/// serialized authority artifacts retained in a build result.
///
/// `C` is recovered from final P730 bytes; `F` is decoded through the shared
/// strict no-std P73K parser used by firmware; and `K` is checked against its
/// canonical count/hash plus the complete all-known Bloom. This is called both
/// before returning a build and before minting P73S.
pub fn prove_forced_eligible_partition(result: &Erc7730BuildResult) -> Result<(), String> {
    let recovered = recover_clear_contract_calls_from_p730(&result.blob)?;
    if recovered.root != result.root {
        return Err("P730 reconstructed root disagrees with build result".to_string());
    }
    if recovered.leaf_count != result.leaf_count {
        return Err(format!(
            "P730 reconstructed leaf count {} != build result {}",
            recovered.leaf_count, result.leaf_count
        ));
    }
    if recovered.calls.len() != result.clear_contract_call_count {
        return Err(format!(
            "P730 clear tuple count {} != retained count {}",
            recovered.calls.len(),
            result.clear_contract_call_count
        ));
    }

    if result.known_calls.len() != result.known_call_count {
        return Err(format!(
            "K vector length {} != retained count {}",
            result.known_calls.len(),
            result.known_call_count
        ));
    }
    if result.known_calls.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("K vector is duplicate or not strictly sorted".to_string());
    }
    let known: BTreeSet<ContractCallTuple> = result.known_calls.iter().copied().collect();
    if known_call_set_hash(&known)? != result.known_call_set_hash {
        return Err("K vector does not reproduce P73S known-call set hash".to_string());
    }

    let forced = ForcedEligibleSet::from_bytes(&result.forced_eligible_set)
        .map_err(|error| format!("P73K strict decode failed: {error:?}"))?;
    let forced_group_count = usize::try_from(forced.group_count())
        .map_err(|_| "P73K group count does not fit usize".to_string())?;
    let forced_tuple_count = usize::try_from(forced.tuple_count())
        .map_err(|_| "P73K tuple count does not fit usize".to_string())?;
    if forced_group_count != result.forced_eligible_group_count {
        return Err(format!(
            "P73K group count {} != retained count {}",
            forced_group_count, result.forced_eligible_group_count
        ));
    }
    if forced_tuple_count != result.forced_eligible_count {
        return Err(format!(
            "P73K tuple count {} != retained count {}",
            forced_tuple_count, result.forced_eligible_count
        ));
    }
    let forced_calls: Vec<ContractCallTuple> = forced.iter().collect();
    if forced_calls.len() != result.forced_eligible_count {
        return Err("P73K iterator count disagrees with authenticated header".to_string());
    }
    if encode_forced_eligible_set(&forced_calls)? != result.forced_eligible_set {
        return Err("P73K bytes are not the canonical encoding of decoded F".to_string());
    }

    let clear: BTreeSet<ContractCallTuple> = recovered.calls.iter().copied().collect();
    let forced_set: BTreeSet<ContractCallTuple> = forced_calls.iter().copied().collect();
    if let Some((chain_id, contract, selector)) = clear.intersection(&forced_set).next() {
        return Err(format!(
            "C/F overlap at chain={chain_id} contract=0x{} selector=0x{}",
            hex::encode(contract),
            hex::encode(selector)
        ));
    }
    let merged: Vec<ContractCallTuple> = clear.union(&forced_set).copied().collect();
    if merged != result.known_calls {
        return Err("canonical C/F merge does not reconstruct K byte-for-byte".to_string());
    }
    if merged.len() != result.known_call_count {
        return Err("C/F union does not reproduce P73S known-call count".to_string());
    }
    if known_call_set_hash(&merged.iter().copied().collect())? != result.known_call_set_hash {
        return Err("C/F union does not reproduce P73S known-call set hash".to_string());
    }
    for (chain_id, contract, selector) in &merged {
        if !known_call_may_contain(&result.known_calls_bloom, *chain_id, contract, selector) {
            return Err(format!(
                "all-known Bloom is negative for union tuple chain={chain_id} contract=0x{} selector=0x{}",
                hex::encode(contract),
                hex::encode(selector)
            ));
        }
    }
    Ok(())
}

/// Round-trip every emitted IR back through the on-device parser +
/// Merkle verifier. Catches every shape of format drift between the
/// host compiler and `pqsigner_erc7730::bundle::verify_erc7730_bundle`.
pub fn round_trip_check(result: &Erc7730BuildResult) -> Result<(), String> {
    for e in &result.entries {
        // Parse the IR via the canonical on-device parser.
        let ir = Erc7730Ir::parse(&e.ir_bytes).map_err(|err| {
            format!(
                "round-trip parse failed for {}: {err:?}",
                e.source.display()
            )
        })?;
        if ir.chain_id != e.chain_id {
            return Err(format!(
                "round-trip chain_id mismatch in {}: wrote {} read {}",
                e.source.display(),
                e.chain_id,
                ir.chain_id
            ));
        }
        if ir.contract != e.contract {
            return Err(format!(
                "round-trip contract mismatch in {}: wrote 0x{} read 0x{}",
                e.source.display(),
                hex::encode(e.contract),
                hex::encode(ir.contract)
            ));
        }
        if ir.descriptor_hash != e.descriptor_hash {
            return Err(format!(
                "round-trip descriptor_hash mismatch in {}",
                e.source.display()
            ));
        }

        // Walk the proof region back to the root.
        let proof = extract_proof(
            &result.blob,
            e.leaf_index,
            result_proof_depth(&result.blob)?,
        )?;
        if !verify_proof_via_dbgen(&e.ir_bytes, e.leaf_index, &proof, &result.root) {
            return Err(format!(
                "round-trip dbgen-Merkle proof failed for {}",
                e.source.display()
            ));
        }

        // Also exercise the on-device bundle verifier with a synthetic
        // trailer.
        let bundle = synth_bundle(&e.ir_bytes, e.leaf_index as u32, &proof);
        verify_erc7730_bundle_with_leaf_count(&bundle, &result.root, result.leaf_count).map_err(
            |err| {
                format!(
                    "round-trip on-device bundle verify failed for {}: {err:?}",
                    e.source.display()
                )
            },
        )?;

        if e.context_kind == CTX_CONTRACT {
            for format in ir.format_iter() {
                let format = format.map_err(|err| {
                    format!(
                        "round-trip known-call format failed for {}: {err:?}",
                        e.source.display()
                    )
                })?;
                if !known_call_may_contain(
                    &result.known_calls_bloom,
                    e.chain_id,
                    &e.contract,
                    &format.selector,
                ) {
                    return Err(format!(
                        "round-trip known-call false negative for {} selector 0x{}",
                        e.source.display(),
                        hex::encode(format.selector),
                    ));
                }
            }
        }
    }
    prove_forced_eligible_partition(result)
}

fn result_proof_depth(blob: &[u8]) -> Result<usize, String> {
    if blob.len() < ERC7730_DB_HEADER_LEN {
        return Err("blob too small for header".to_string());
    }
    let pd = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    Ok(pd)
}

fn extract_proof(
    blob: &[u8],
    leaf_index: usize,
    proof_depth: usize,
) -> Result<Vec<[u8; 32]>, String> {
    let entry_cnt = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    if leaf_index >= entry_cnt {
        return Err(format!("leaf_index {leaf_index} >= entry_cnt {entry_cnt}"));
    }
    let base = proofs_off + leaf_index * proof_depth * 32;
    if base + proof_depth * 32 > blob.len() {
        return Err("proof region out of bounds".to_string());
    }
    let mut out = Vec::with_capacity(proof_depth);
    for j in 0..proof_depth {
        let off = base + j * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&blob[off..off + 32]);
        out.push(h);
    }
    Ok(out)
}

fn verify_proof_via_dbgen(
    ir_bytes: &[u8],
    leaf_index: usize,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    // Wraps `dbgen::merkle::verify_proof`, whose canonical input is
    // the raw leaf bytes (and which then prefixes 0x00 internally — the
    // same scheme as `pqsigner_erc7730::bundle::leaf_hash`).
    verify_proof(ir_bytes, leaf_index, proof, root)
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

// ─────────────────────────────────────────────────────────────────────
// Per-descriptor compilation.
// ─────────────────────────────────────────────────────────────────────

fn load_resolved_descriptor_json(
    path: &Path,
    registry_root: Option<&Path>,
) -> Result<serde_json::Value, String> {
    let mut snapshot = DescriptorSourceSnapshot::default();
    load_resolved_descriptor_json_from_snapshot(path, registry_root, &mut snapshot)
}

fn load_resolved_descriptor_json_from_snapshot(
    path: &Path,
    registry_root: Option<&Path>,
    snapshot: &mut DescriptorSourceSnapshot,
) -> Result<serde_json::Value, String> {
    let mut json = snapshot.load_json(path)?;

    // Resolve top-level includes before either compilation or the independent
    // registry-known-call scan. Keeping one loader prevents a skipped format
    // from disappearing merely because its declarations came from a template.
    let mut depth = 0usize;
    // Each nested include is relative to the file that declared it, not the
    // original leaf descriptor. Reusing `path` here silently selected a
    // same-named template from the wrong directory when A -> sub/B -> C.
    let mut including_path = path.to_path_buf();
    loop {
        let inc = match json.get("includes") {
            None => break,
            Some(value) => value
                .as_str()
                .ok_or_else(|| "`includes` must be a string".to_string())?
                .to_string(),
        };
        depth += 1;
        if depth > 8 {
            return Err("includes recursion depth > 8 — refusing".to_string());
        }
        let root = registry_root.ok_or_else(|| {
            format!(
                "`includes: \"{inc}\"` requires `--registry-root <dir>`. \
                 See secure/data/erc7730/REGISTRY_MIRROR.md."
            )
        })?;
        let inc_path = resolve_include_path(root, &including_path, &inc)?;
        let inc_json = snapshot
            .load_json(&inc_path)
            .map_err(|e| format!("load include {}: {e}", inc_path.display()))?;
        if let Some(obj) = json.as_object_mut() {
            obj.remove("includes");
        }
        json = merge_descriptors(inc_json, json);
        including_path = inc_path;
    }
    Ok(json)
}

/// Compute the internal descriptor identity from the exact include-resolved
/// source using the same RFC-8785 JCS subset as catalogue compilation.
///
/// This is intentionally a dbgen-owned operation: exact nested-calldata
/// policy rows must bind the hash of the resolved descriptor, rather than a
/// second test/tool implementation of canonical JSON.
pub fn resolved_descriptor_sha256(
    path: &Path,
    registry_root: Option<&Path>,
) -> Result<[u8; 32], String> {
    let json = load_resolved_descriptor_json(path, registry_root)?;
    Ok(sha256_of(&jcs_canonicalize(&json)?))
}

#[cfg(test)]
fn compile_descriptor(
    path: &Path,
    _policy: &Policy,
    registry_root: Option<&Path>,
    tolerant: bool,
    partial_format_drops: &mut Vec<String>,
    erc20_capabilities: &Erc20Capabilities,
    declared_contract_signatures: Option<&DeclaredContractSignatures>,
) -> Result<Vec<Emitted>, String> {
    compile_descriptor_with_nested_calldata_enrollments(
        path,
        _policy,
        registry_root,
        tolerant,
        partial_format_drops,
        erc20_capabilities,
        declared_contract_signatures,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn compile_descriptor_with_nested_calldata_enrollments(
    path: &Path,
    _policy: &Policy,
    registry_root: Option<&Path>,
    tolerant: bool,
    partial_format_drops: &mut Vec<String>,
    erc20_capabilities: &Erc20Capabilities,
    declared_contract_signatures: Option<&DeclaredContractSignatures>,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Result<Vec<Emitted>, String> {
    let json = load_resolved_descriptor_json(path, registry_root)?;
    compile_resolved_descriptor_with_nested_calldata_enrollments(
        path,
        &json,
        _policy,
        tolerant,
        partial_format_drops,
        erc20_capabilities,
        declared_contract_signatures,
        nested_calldata_enrollments,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_resolved_descriptor_with_nested_calldata_enrollments(
    path: &Path,
    json: &serde_json::Value,
    _policy: &Policy,
    tolerant: bool,
    partial_format_drops: &mut Vec<String>,
    erc20_capabilities: &Erc20Capabilities,
    declared_contract_signatures: Option<&DeclaredContractSignatures>,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Result<Vec<Emitted>, String> {
    // `Option<T>` normally treats an explicit JSON `null` like an absent
    // field. That is unsafe for a narrowing extension: a reviewer could see
    // `_pqsigner` in a curated descriptor while the compiler silently emits
    // the ordinary full deployment × format cross-product. Missing means
    // unscoped; present must be a concrete, validated object.
    if json
        .get("_pqsigner")
        .is_some_and(serde_json::Value::is_null)
    {
        return Err("schema: `_pqsigner` must be an object, not null".to_string());
    }

    let descriptor: Descriptor =
        serde_json::from_value(json.clone()).map_err(|e| format!("schema: {e}"))?;
    reject_unsupported_context_semantics(&descriptor.context)?;

    // After include-resolution `descriptor.includes` must be empty.
    if let Some(inc) = descriptor.includes.as_deref() {
        return Err(format!(
            "post-merge: residual `includes: \"{inc}\"` (recursion didn't reach a leaf)"
        ));
    }

    // Compute the descriptor hashes once over the canonical (RFC-8785 JCS)
    // JSON. Two different hashes over the SAME canonical bytes:
    //   - `descriptor_hash` (SHA-256) — the INTERNAL IR/leaf identifier, baked
    //     into the firmware-pinned Merkle tree (SHA-256 per the PQ-stack
    //     convention: "SHA-256 inside the PQ stack, keccak only for EVM").
    //   - `erc8176_hash` (keccak-256) — the ERC-8176 `descriptorHash`: the value
    //     an auditor attests on the Ethereum Attestation Service (EAS schema
    //     0xe023ee…, `bytes32 descriptorHash`). EVM/keccak, HOST-ONLY (the device
    //     never computes it); surfaced in the review file so an auditor can look
    //     each descriptor up on EAS. See `docs/erc8176-attestation-status.md`.
    let jcs = jcs_canonicalize(json)?;
    let descriptor_hash = sha256_of(&jcs);
    let erc8176_hash = pqsigner_tx_core::hash::keccak256(&jcs);

    // Extract the descriptor ID (used for the review file).
    let descriptor_id = descriptor
        .context
        .id
        .clone()
        .or_else(|| descriptor.metadata.contract_name.clone())
        .or_else(|| descriptor.metadata.owner.clone())
        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

    let owner = clean_ascii_truncated(
        descriptor.metadata.owner.as_deref().unwrap_or(""),
        OWNER_FIELD_LEN - 1,
    );
    let contract_name = clean_ascii_truncated(
        descriptor
            .metadata
            .contract_name
            .as_deref()
            .or(descriptor.context.id.as_deref())
            .unwrap_or(""),
        CONTRACT_NAME_FIELD_LEN - 1,
    );

    // Decide context kind + collect deployment tuples before moving metadata
    // into the compile context: the local curation constraint is validated
    // against the exact resolved source declarations, never against a
    // best-effort string match during leaf emission.
    let (context_kind, deployments) =
        resolve_deployments(&descriptor.context).map_err(|e| format!("deployments: {e}"))?;
    let eip712_word_guard_source_required = eip712_word_guard_source_required(path);
    if eip712_word_guard_source_required && context_kind != CTX_EIP712 {
        return Err(format!(
            "descriptor source `{}` requires exact EIP-712 word-guard enrollment",
            path.display()
        ));
    }
    let deployment_formats = validate_deployment_format_admissions(
        descriptor.pqsigner.as_ref(),
        context_kind,
        &deployments,
        &descriptor.display,
        declared_contract_signatures,
    )?;
    let refusal_only_formats = validate_refusal_only_formats(
        descriptor.pqsigner.as_ref(),
        context_kind,
        &descriptor.display,
    )?;
    let threshold_omissions = validate_threshold_omissions(
        descriptor.pqsigner.as_ref(),
        context_kind,
        &deployments,
        &descriptor.display,
    )?;

    // Resolve constants and enums into the IR pool (lazily, only
    // entries actually referenced get emitted).
    let base_ctx = CompileCtx {
        constants: descriptor.metadata.constants.unwrap_or_default(),
        enums: descriptor.metadata.enums.unwrap_or_default(),
        descriptor_hash,
        owner: owner.clone(),
        contract_name: contract_name.clone(),
        eip712_word_guard_source_required,
    };

    // Interpolation enrollment can differ by deployment: a static token may
    // be authenticated on one chain but absent from the exact ERC-20 metadata
    // corpus on another. Compile each body against its deployment capability
    // rather than cloning one optimistic body across every chain.
    let mut out = Vec::with_capacity(deployments.len());
    let mut recorded_partial_drops = BTreeSet::new();
    for dep in deployments {
        let (chain_id, contract_addr, domain_separator) =
            resolve_per_deployment(context_kind, &descriptor.context, &dep)?;
        let allowed_formats = match deployment_formats.as_ref() {
            None => None,
            Some(admissions) => match admissions.get(&(chain_id, contract_addr)) {
                Some(formats) => Some(formats),
                None => {
                    partial_format_drops.push(format!(
                        "deployment chain_id={chain_id} contract=0x{} excluded by the authenticated PQSigner deploymentFormats allowlist",
                        hex::encode(contract_addr)
                    ));
                    continue;
                }
            },
        };
        if context_kind == CTX_EIP712
            && (deployment_formats.is_some() || !refusal_only_formats.is_empty())
            && !descriptor.display.formats.keys().any(|signature| {
                !refusal_only_formats.contains(signature)
                    && allowed_formats.is_none_or(|allowed| allowed.contains(signature))
            })
        {
            partial_format_drops.push(format!(
                "deployment chain_id={chain_id} contract=0x{} has zero EIP-712 formats after authenticated PQSigner deploymentFormats/refusalOnlyFormats curation; deployment skipped",
                hex::encode(contract_addr)
            ));
            continue;
        }
        let deployment = InterpolationDeployment {
            chain_id,
            contract: contract_addr,
            erc20_capabilities,
        };
        let mut ctx = base_ctx.clone();
        let mut deployment_drops = Vec::new();
        let narrowed_display = threshold_omissions
            .get(&(chain_id, contract_addr))
            .map(|omitted| display_without_thresholds(&descriptor.display, omitted));
        let (formats_section, pool_initial) =
            compile_formats_reporting_with_nested_calldata_enrollments(
                narrowed_display.as_ref().unwrap_or(&descriptor.display),
                context_kind,
                &mut ctx,
                tolerant,
                &mut deployment_drops,
                Some(&deployment),
                allowed_formats,
                &refusal_only_formats,
                nested_calldata_enrollments,
            )?;
        // The same unsupported source format is normally rediscovered for
        // every deployment. Keep one stable review receipt per exact reason.
        for reason in deployment_drops {
            if recorded_partial_drops.insert(reason.clone()) {
                partial_format_drops.push(reason);
            }
        }

        let ir_bytes = build_ir(
            context_kind,
            chain_id,
            contract_addr,
            &domain_separator,
            &ctx,
            &pool_initial,
            &formats_section,
        )?;

        if ir_bytes.len() > MAX_IR_LEN {
            return Err(format!(
                "IR {} exceeds MAX_IR_LEN ({} > {})",
                descriptor_id,
                ir_bytes.len(),
                MAX_IR_LEN
            ));
        }

        // Deep-parse every newly built deployment IR with the canonical
        // device parser before it can leave this per-descriptor boundary.
        // In tolerant mode a host/device grammar or policy mismatch therefore
        // drops this descriptor with its ordinary skip receipt instead of
        // poisoning the catalogue later during global processing.
        let parsed_ir = Erc7730Ir::parse(&ir_bytes).map_err(|error| {
            format!(
                "internal: newly emitted IR for `{descriptor_id}` deployment chain_id={chain_id} contract=0x{} failed canonical device parsing: {error:?}",
                hex::encode(contract_addr),
            )
        })?;

        // The catalogue discriminator must name an authenticated format that
        // actually survived tolerant compilation. Indexing by the first source
        // format can orphan an otherwise-valid leaf when that format is one of
        // the fail-closed drops.
        let primary_type_hash = if context_kind == CTX_EIP712 {
            parsed_ir
                .format_iter()
                .next()
                .ok_or_else(|| "internal: emitted EIP-712 IR has no formats".to_string())?
                .map_err(|e| format!("internal: first emitted EIP-712 format is invalid: {e:?}"))?
                .type_hash
        } else {
            [0u8; 32]
        };

        out.push(Emitted {
            source: path.to_path_buf(),
            descriptor_id: descriptor_id.clone(),
            descriptor_hash,
            erc8176_hash,
            chain_id,
            contract: contract_addr,
            context_kind,
            primary_type_hash,
            ir_bytes,
            leaf_index: 0, // filled in by build_db after sorting
        });
    }

    Ok(out)
}

fn resolve_deployments(ctx: &Context) -> Result<(u8, Vec<Deployment>), String> {
    if ctx.contract.is_some() && ctx.eip712.is_some() {
        return Err(
            "context carries both `contract` and `eip712` — refusing ambiguous binding".to_string(),
        );
    }
    if let Some(c) = &ctx.contract {
        if c.deployments.is_empty() {
            return Err("contract.deployments is empty".to_string());
        }
        Ok((
            CTX_CONTRACT,
            c.deployments
                .iter()
                .map(|d| Deployment {
                    chain_id: d.chain_id,
                    address: d.address.clone(),
                })
                .collect(),
        ))
    } else if let Some(e) = &ctx.eip712 {
        let from_deployments = e.deployments.clone().unwrap_or_default();
        let from_domain = match (&e.domain, &e.domain_separator) {
            (
                Some(Eip712Domain {
                    chain_id: Some(cid),
                    verifying_contract: Some(addr),
                    ..
                }),
                _,
            ) => vec![Deployment {
                chain_id: *cid,
                address: addr.clone(),
            }],
            _ => Vec::new(),
        };
        let merged: Vec<Deployment> = if !from_deployments.is_empty() {
            from_deployments
        } else if !from_domain.is_empty() {
            from_domain
        } else {
            return Err(
                "eip712 context lacks both `deployments` and a fully-specified `domain.{chainId,verifyingContract}`"
                    .to_string(),
            );
        };
        Ok((CTX_EIP712, merged))
    } else {
        Err("context has neither `contract` nor `eip712`".to_string())
    }
}

type DeploymentFormatAdmissions = BTreeMap<(u64, [u8; 20]), BTreeSet<String>>;

/// Validate the PQSigner-local deployment/format allowlist and lower its
/// address/string declarations into exact binary catalogue bindings.
///
/// The extension is deliberately monotone: every admitted tuple and format
/// must already exist in the ordinary descriptor. Omitting a deployment or
/// format can only remove clear-signing authority. Contract contexts retain
/// every original tuple in the independent known-call hard-refusal inventory;
/// EIP-712 dispatch remains authenticated by its full type hash and never uses
/// the contract selector/collision path below.
fn validate_deployment_format_admissions(
    pqsigner: Option<&PqsignerCuration>,
    context_kind: u8,
    deployments: &[Deployment],
    display: &Display,
    declared_contract_signatures: Option<&DeclaredContractSignatures>,
) -> Result<Option<DeploymentFormatAdmissions>, String> {
    let Some(pqsigner) = pqsigner else {
        return Ok(None);
    };
    if pqsigner.deployment_formats.is_empty()
        && pqsigner.refusal_only_formats.is_empty()
        && pqsigner.threshold_omissions.is_empty()
    {
        return Err(
            "_pqsigner.deploymentFormats must not be empty unless refusalOnlyFormats or thresholdOmissions is non-empty"
                .to_string(),
        );
    }
    if pqsigner.deployment_formats.is_empty() {
        return Ok(None);
    }
    if context_kind == CTX_EIP712 {
        let mut declared_deployments = BTreeSet::new();
        for (index, deployment) in deployments.iter().enumerate() {
            let address = parse_address(&deployment.address).map_err(|error| {
                format!(
                    "resolved context.eip712 deployment[{index}] address is invalid while validating _pqsigner.deploymentFormats: {error}"
                )
            })?;
            declared_deployments.insert((deployment.chain_id, address));
        }

        let mut admissions = BTreeMap::new();
        for (index, admission) in pqsigner.deployment_formats.iter().enumerate() {
            let address = parse_address(&admission.address).map_err(|error| {
                format!("_pqsigner.deploymentFormats[{index}].address is invalid: {error}")
            })?;
            let binding = (admission.chain_id, address);
            if !declared_deployments.contains(&binding) {
                return Err(format!(
                    "_pqsigner.deploymentFormats[{index}] chain_id={} contract=0x{} is not a declared EIP-712 deployment",
                    admission.chain_id,
                    hex::encode(address)
                ));
            }
            if admission.formats.is_empty() {
                return Err(format!(
                    "_pqsigner.deploymentFormats[{index}].formats must not be empty"
                ));
            }

            let mut formats = BTreeSet::new();
            for (format_index, signature) in admission.formats.iter().enumerate() {
                if !display.formats.contains_key(signature) {
                    return Err(format!(
                        "_pqsigner.deploymentFormats[{index}].formats[{format_index}] names unknown format `{signature}`"
                    ));
                }
                if !formats.insert(signature.clone()) {
                    return Err(format!(
                        "_pqsigner.deploymentFormats[{index}].formats duplicates `{signature}`"
                    ));
                }
            }
            if admissions.insert(binding, formats).is_some() {
                return Err(format!(
                    "_pqsigner.deploymentFormats duplicates chain_id={} contract=0x{}",
                    admission.chain_id,
                    hex::encode(address)
                ));
            }
        }

        return Ok(Some(admissions));
    }
    if context_kind != CTX_CONTRACT {
        return Err("_pqsigner.deploymentFormats is contract-context only".to_string());
    }

    let mut declared_deployments = BTreeSet::new();
    for (index, deployment) in deployments.iter().enumerate() {
        let address = parse_address(&deployment.address).map_err(|error| {
            format!(
                "context.contract.deployments[{index}] address is invalid while validating _pqsigner.deploymentFormats: {error}"
            )
        })?;
        declared_deployments.insert((deployment.chain_id, address));
    }

    // An EVM call is dispatched by its four-byte selector, not by the source
    // signature string used as the ERC-7730 format key. Narrowing one of two
    // colliding signatures would otherwise authenticate the selected decoder
    // for calldata intended for the omitted signature, while the known-call
    // filter could not distinguish them. Precompute every source collision and
    // refuse any admission that selects a member of one.
    let mut source_formats_by_selector = BTreeMap::<[u8; 4], Vec<String>>::new();
    for signature in display.formats.keys() {
        let canonical = contract_selector_signature(signature).map_err(|error| {
            format!(
                "format `{signature}` cannot be selector-bound while validating _pqsigner.deploymentFormats: {error}"
            )
        })?;
        let digest = keccak256(canonical.as_bytes());
        source_formats_by_selector
            .entry([digest[0], digest[1], digest[2], digest[3]])
            .or_default()
            .push(signature.clone());
    }

    let mut admissions = BTreeMap::new();
    for (index, admission) in pqsigner.deployment_formats.iter().enumerate() {
        let address = parse_address(&admission.address).map_err(|error| {
            format!("_pqsigner.deploymentFormats[{index}].address is invalid: {error}")
        })?;
        let binding = (admission.chain_id, address);
        if !declared_deployments.contains(&binding) {
            return Err(format!(
                "_pqsigner.deploymentFormats[{index}] chain_id={} contract=0x{} is not a declared contract deployment",
                admission.chain_id,
                hex::encode(address)
            ));
        }
        if admission.formats.is_empty() {
            return Err(format!(
                "_pqsigner.deploymentFormats[{index}].formats must not be empty"
            ));
        }

        let mut formats = BTreeSet::new();
        for (format_index, signature) in admission.formats.iter().enumerate() {
            if !display.formats.contains_key(signature) {
                return Err(format!(
                    "_pqsigner.deploymentFormats[{index}].formats[{format_index}] names unknown format `{signature}`"
                ));
            }
            let canonical = contract_selector_signature(signature).map_err(|error| {
                format!(
                    "_pqsigner.deploymentFormats[{index}].formats[{format_index}] cannot be selector-bound: {error}"
                )
            })?;
            let digest = keccak256(canonical.as_bytes());
            let selector = [digest[0], digest[1], digest[2], digest[3]];
            let colliders = source_formats_by_selector
                .get(&selector)
                .expect("selected source format was inventoried above");
            if colliders.len() != 1 {
                return Err(format!(
                    "_pqsigner.deploymentFormats[{index}].formats[{format_index}] selects `{signature}` with selector 0x{}, which collides with source formats {:?}; selector-only runtime dispatch cannot authenticate this narrowing",
                    hex::encode(selector),
                    colliders
                ));
            }
            if let Some(declared_contract_signatures) = declared_contract_signatures {
                let key = (admission.chain_id, address, selector);
                let catalogue_signatures = declared_contract_signatures.get(&key).ok_or_else(|| {
                    format!(
                        "internal: selected `{signature}` has no catalogue-wide source-signature inventory for chain_id={} contract=0x{} selector=0x{}",
                        admission.chain_id,
                        hex::encode(address),
                        hex::encode(selector)
                    )
                })?;
                if catalogue_signatures.len() != 1 || !catalogue_signatures.contains(&canonical) {
                    return Err(format!(
                        "_pqsigner.deploymentFormats[{index}].formats[{format_index}] selects `{signature}` for chain_id={} contract=0x{} selector=0x{}, which collides catalogue-wide with canonical source signatures {:?}; selector-only runtime dispatch cannot authenticate this narrowing",
                        admission.chain_id,
                        hex::encode(address),
                        hex::encode(selector),
                        catalogue_signatures
                    ));
                }
            }
            if !formats.insert(signature.clone()) {
                return Err(format!(
                    "_pqsigner.deploymentFormats[{index}].formats duplicates `{signature}`"
                ));
            }
        }
        if admissions.insert(binding, formats).is_some() {
            return Err(format!(
                "_pqsigner.deploymentFormats duplicates chain_id={} contract=0x{}",
                admission.chain_id,
                hex::encode(address)
            ));
        }
    }

    Ok(Some(admissions))
}

/// Validate exact source formats that are structurally refusal-only.
///
/// The marker is authenticated as part of the descriptor JCS hash. It only
/// narrows authority: the independent source inventory still contributes
/// every declared deployment/selector tuple to the exact known-call set, while
/// this set is removed before IR compilation. An overlap with
/// `deploymentFormats` is rejected so no later reader has to resolve
/// contradictory local policy.
/// Validate `_pqsigner.thresholdOmissions` against the exact resolved source
/// declarations. Contract context only; every entry must name a declared
/// deployment, an existing format, and a direct (non-`$ref`, non-group) field
/// of that format with `tokenAmount` format whose params carry `threshold`.
/// Duplicates are refused so a review receipt cannot double-count an entry.
fn validate_threshold_omissions(
    pqsigner: Option<&PqsignerCuration>,
    context_kind: u8,
    deployments: &[Deployment],
    display: &Display,
) -> Result<ThresholdOmissions, String> {
    let mut out = ThresholdOmissions::new();
    let Some(pqsigner) = pqsigner else {
        return Ok(out);
    };
    if pqsigner.threshold_omissions.is_empty() {
        return Ok(out);
    }
    if context_kind != CTX_CONTRACT {
        return Err("_pqsigner.thresholdOmissions is contract-context only".to_string());
    }
    let mut declared_deployments = BTreeSet::new();
    for (index, deployment) in deployments.iter().enumerate() {
        let address = parse_address(&deployment.address).map_err(|error| {
            format!(
                "context.contract.deployments[{index}] address is invalid while validating _pqsigner.thresholdOmissions: {error}"
            )
        })?;
        declared_deployments.insert((deployment.chain_id, address));
    }
    for (index, omission) in pqsigner.threshold_omissions.iter().enumerate() {
        let address = parse_address(&omission.address).map_err(|error| {
            format!("_pqsigner.thresholdOmissions[{index}].address is invalid: {error}")
        })?;
        let binding = (omission.chain_id, address);
        if !declared_deployments.contains(&binding) {
            return Err(format!(
                "_pqsigner.thresholdOmissions[{index}] chain_id={} contract=0x{} is not a declared contract deployment",
                omission.chain_id,
                hex::encode(address)
            ));
        }
        let Some(format) = display.formats.get(&omission.format) else {
            return Err(format!(
                "_pqsigner.thresholdOmissions[{index}] names unknown format `{}`",
                omission.format
            ));
        };
        let mut matches = format
            .fields
            .iter()
            .filter(|field| field.path.as_deref() == Some(omission.path.as_str()));
        let (Some(field), None) = (matches.next(), matches.next()) else {
            return Err(format!(
                "_pqsigner.thresholdOmissions[{index}] must name exactly one direct field `{}` in `{}`",
                omission.path, omission.format
            ));
        };
        if field.ref_def.is_some()
            || field.fields.is_some()
            || field.format.as_deref() != Some("tokenAmount")
            || !field
                .params
                .as_ref()
                .and_then(|params| params.as_object())
                .is_some_and(|params| params.contains_key("threshold"))
        {
            return Err(format!(
                "_pqsigner.thresholdOmissions[{index}] field `{}` in `{}` is not a direct tokenAmount field carrying a threshold",
                omission.path, omission.format
            ));
        }
        if !out
            .entry(binding)
            .or_default()
            .insert((omission.format.clone(), omission.path.clone()))
        {
            return Err(format!(
                "_pqsigner.thresholdOmissions duplicates chain_id={} contract=0x{} `{}` `{}`",
                omission.chain_id,
                hex::encode(address),
                omission.format,
                omission.path
            ));
        }
    }
    Ok(out)
}

/// A copy of `display` with the validated threshold/message shorthand removed
/// from each omitted `(format, path)` field. Narrowing only: no other key moves.
fn display_without_thresholds(display: &Display, omitted: &BTreeSet<(String, String)>) -> Display {
    let mut narrowed = display.clone();
    for (signature, format) in &mut narrowed.formats {
        for field in &mut format.fields {
            let Some(path) = field.path.as_deref() else {
                continue;
            };
            if !omitted.contains(&(signature.clone(), path.to_string())) {
                continue;
            }
            if let Some(params) = field.params.as_mut().and_then(|p| p.as_object_mut()) {
                params.remove("threshold");
                params.remove("message");
            }
        }
    }
    narrowed
}

fn validate_refusal_only_formats(
    pqsigner: Option<&PqsignerCuration>,
    context_kind: u8,
    display: &Display,
) -> Result<BTreeSet<String>, String> {
    let Some(pqsigner) = pqsigner else {
        return Ok(BTreeSet::new());
    };
    if pqsigner.refusal_only_formats.is_empty() {
        return Ok(BTreeSet::new());
    }
    if context_kind == CTX_EIP712 {
        let admitted = pqsigner
            .deployment_formats
            .iter()
            .flat_map(|admission| admission.formats.iter())
            .collect::<BTreeSet<_>>();
        let mut refusal_only = BTreeSet::new();
        for (index, signature) in pqsigner.refusal_only_formats.iter().enumerate() {
            if !display.formats.contains_key(signature) {
                return Err(format!(
                    "_pqsigner.refusalOnlyFormats[{index}] names unknown format `{signature}`"
                ));
            }
            if admitted.contains(signature) {
                return Err(format!(
                    "_pqsigner.refusalOnlyFormats[{index}] overlaps deploymentFormats at `{signature}`"
                ));
            }
            if !refusal_only.insert(signature.clone()) {
                return Err(format!(
                    "_pqsigner.refusalOnlyFormats duplicates `{signature}`"
                ));
            }
        }
        return Ok(refusal_only);
    }
    if context_kind != CTX_CONTRACT {
        return Err("_pqsigner.refusalOnlyFormats is contract-context only".to_string());
    }

    let admitted = pqsigner
        .deployment_formats
        .iter()
        .flat_map(|admission| admission.formats.iter())
        .collect::<BTreeSet<_>>();
    let mut source_formats_by_selector = BTreeMap::<[u8; 4], Vec<String>>::new();
    for signature in display.formats.keys() {
        let canonical = contract_selector_signature(signature).map_err(|error| {
            format!(
                "format `{signature}` cannot be selector-bound while validating _pqsigner.refusalOnlyFormats: {error}"
            )
        })?;
        let digest = keccak256(canonical.as_bytes());
        source_formats_by_selector
            .entry([digest[0], digest[1], digest[2], digest[3]])
            .or_default()
            .push(signature.clone());
    }

    let mut refusal_only = BTreeSet::new();
    for (index, signature) in pqsigner.refusal_only_formats.iter().enumerate() {
        if !display.formats.contains_key(signature) {
            return Err(format!(
                "_pqsigner.refusalOnlyFormats[{index}] names unknown format `{signature}`"
            ));
        }
        let canonical = contract_selector_signature(signature).map_err(|error| {
            format!("_pqsigner.refusalOnlyFormats[{index}] cannot be selector-bound: {error}")
        })?;
        let digest = keccak256(canonical.as_bytes());
        let selector = [digest[0], digest[1], digest[2], digest[3]];
        let colliders = source_formats_by_selector
            .get(&selector)
            .expect("refusal-only source format was inventoried above");
        if colliders.len() != 1 {
            return Err(format!(
                "_pqsigner.refusalOnlyFormats[{index}] selects `{signature}` with selector 0x{}, which collides with source formats {:?}; selector-only runtime dispatch cannot authenticate this refusal boundary",
                hex::encode(selector),
                colliders
            ));
        }
        if admitted.contains(signature) {
            return Err(format!(
                "_pqsigner.refusalOnlyFormats[{index}] overlaps deploymentFormats at `{signature}`"
            ));
        }
        if !refusal_only.insert(signature.clone()) {
            return Err(format!(
                "_pqsigner.refusalOnlyFormats duplicates `{signature}`"
            ));
        }
    }
    Ok(refusal_only)
}

fn reject_unsupported_context_semantics(ctx: &Context) -> Result<(), String> {
    if let Some(contract) = &ctx.contract {
        if contract.proxy.is_some() {
            return Err(
                "schema: `context.contract.proxy` is unsupported: the firmware binds only the \
                 deployment address and cannot authenticate a mutable proxy implementation"
                    .to_string(),
            );
        }
        if contract.state_refs.is_some() {
            return Err(
                "schema: `context.contract.stateRefs` is unsupported: the offline firmware \
                 cannot authenticate descriptor state preconditions"
                    .to_string(),
            );
        }
    }
    if let Some(eip712) = ctx.eip712.as_ref() {
        if eip712.domain_separator.is_some() {
            return Err(
                "schema: `context.eip712.domainSeparator` is unsupported: an arbitrary explicit \
                 separator cannot prove the deployment chainId/verifyingContract binding; provide \
                 `domain` fields and let dbgen compute the canonical separator per deployment"
                    .to_string(),
            );
        }
        if eip712.schemas.is_some() {
            return Err(
                "schema: `context.eip712.schemas` is unsupported and cannot be ignored because it \
                 changes typed-data interpretation"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn resolve_per_deployment(
    context_kind: u8,
    ctx: &Context,
    dep: &Deployment,
) -> Result<(u64, [u8; 20], [u8; 32]), String> {
    let contract = parse_address(&dep.address)?;
    if context_kind == CTX_CONTRACT {
        return Ok((dep.chain_id, contract, [0u8; 32]));
    }
    // EIP-712 path: compute the deployment-bound domain separator. The
    // catalogue discriminator is derived later from emitted IR, after
    // tolerant format filtering.
    let eip = ctx
        .eip712
        .as_ref()
        .ok_or_else(|| "expected eip712 context".to_string())?;
    // `reject_unsupported_context_semantics` has already refused an explicit
    // `domainSeparator`. Compute the only accepted form canonically from the
    // descriptor's declared domain shape, overriding the two deployment-bound
    // fields for EVERY leaf so neither can drift from the emitted header.
    let mut domain = eip.domain.clone().unwrap_or_default();
    domain.chain_id = Some(dep.chain_id);
    domain.verifying_contract = Some(dep.address.clone());
    let domain_sep = compute_domain_separator(&domain)?;

    Ok((dep.chain_id, contract, domain_sep))
}

// ─────────────────────────────────────────────────────────────────────
// Format / field compilation.
// ─────────────────────────────────────────────────────────────────────

/// Side-table the compiler builds while walking a single descriptor.
#[derive(Clone)]
struct CompileCtx {
    constants: serde_json::Map<String, serde_json::Value>,
    enums: serde_json::Map<String, serde_json::Value>,
    #[allow(dead_code)]
    descriptor_hash: [u8; 32],
    #[allow(dead_code)]
    owner: String,
    #[allow(dead_code)]
    contract_name: String,
    /// A source-path policy boundary independent of descriptor/deployment/type
    /// bytes. Every admitted EIP-712 format from this source must match one
    /// exact word-guard enrollment or fail closed.
    eip712_word_guard_source_required: bool,
}

/// Deployment-bound interpolation authority. The ERC-20 key set comes from
/// the exact validated DB build whose Merkle root will be authenticated by the
/// device; no runtime lookup success is assumed here.
#[derive(Clone, Copy)]
struct InterpolationDeployment<'a> {
    chain_id: u64,
    contract: [u8; 20],
    erc20_capabilities: &'a Erc20Capabilities,
}

/// Pool-with-cache used while compiling a single descriptor. Interns
/// repeated paths / param blobs to keep the IR compact (the seed
/// corpus has plenty of repeated `"@.to"` / `["eoa","contract"]`
/// addressName params).
struct Pool {
    buf: Vec<u8>,
    interned: BTreeMap<Vec<u8>, u16>,
}

impl Pool {
    fn new() -> Self {
        // Reserve offset 0 with a 1-byte filler so it can never be the
        // address of a real interned entry. The on-device path reader
        // (`pqsigner_erc7730::ir::Erc7730Ir::path_bytes`) and renderer
        // (`secure/src/tx/display/erc7730/formatters::resolve_path` +
        // `secure/src/tx/erc7730_render/params::parse_params`) all treat
        // `path_off == 0` / `param_off == 0` as "no path" / "default
        // params" sentinels. Without this filler, the first interned
        // path program would collide with the sentinel and the renderer
        // would fall through to blind-sign with a "7730 missing path"
        // banner.
        Self {
            buf: vec![0xFFu8],
            interned: BTreeMap::new(),
        }
    }

    /// Push raw bytes (no interning). Returns the offset, or an error
    /// if the resulting offset would overflow u16.
    fn push_raw(&mut self, bytes: &[u8]) -> Result<u16, String> {
        let off = self.buf.len();
        if off + bytes.len() > u16::MAX as usize {
            return Err(format!(
                "IR pool overflow ({} + {} > {})",
                off,
                bytes.len(),
                u16::MAX
            ));
        }
        self.buf.extend_from_slice(bytes);
        Ok(off as u16)
    }

    /// Intern a byte slice — returns the existing offset if already
    /// present, otherwise pushes and returns the new offset.
    fn intern(&mut self, bytes: &[u8]) -> Result<u16, String> {
        if let Some(&off) = self.interned.get(bytes) {
            return Ok(off);
        }
        let off = self.push_raw(bytes)?;
        self.interned.insert(bytes.to_vec(), off);
        Ok(off)
    }

    /// Return a new canonical parameter blob consisting of the existing blob
    /// plus one TLV. The old interned entry is never mutated: other fields may
    /// share its offset, and changing it in place would silently give them
    /// format-level interpolation semantics too.
    fn append_param_tlv(
        &mut self,
        param_off: u16,
        kind: u8,
        payload: &[u8],
    ) -> Result<u16, String> {
        let mut body = Vec::new();
        if param_off != 0 {
            let off = param_off as usize;
            let len = *self
                .buf
                .get(off)
                .ok_or_else(|| "existing param offset is outside the IR pool".to_string())?
                as usize;
            let existing = self
                .buf
                .get(off + 1..off + 1 + len)
                .ok_or_else(|| "existing param blob is truncated".to_string())?;
            body.extend_from_slice(existing);
        }
        push_tlv(&mut body, kind, payload)?;
        if body.len() > MAX_POOL_TLV_PAYLOAD {
            return Err(format!(
                "parameter blob with TLV 0x{kind:02x} is {} bytes; maximum is {MAX_POOL_TLV_PAYLOAD}",
                body.len()
            ));
        }
        let mut encoded = Vec::with_capacity(1 + body.len());
        encoded.push(body.len() as u8);
        encoded.extend_from_slice(&body);
        self.intern(&encoded)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// First unmodelled top-level key across `fields` (recursing into field
/// GROUPS), or `None`. Feeds the 1.3 gate: a `fields[]`-element key dbgen
/// doesn't model would otherwise be silently dropped, changing what a trusted
/// clear-sign renders (the `$ref` failure class, finding 1.1).
fn first_unmodeled_field_key(fields: &[FieldDef]) -> Option<String> {
    for f in fields {
        if let Some(k) = f.unknown.keys().next() {
            return Some(k.clone());
        }
        if let Some(children) = &f.fields {
            if let Some(inner) = first_unmodeled_field_key(children) {
                return Some(inner);
            }
        }
    }
    None
}

#[cfg(test)]
fn compile_formats(
    display: &Display,
    context_kind: u8,
    ctx: &mut CompileCtx,
    tolerant: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    compile_formats_reporting(
        display,
        context_kind,
        ctx,
        tolerant,
        &mut Vec::new(),
        None,
        None,
    )
}

#[cfg(test)]
fn compile_formats_reporting(
    display: &Display,
    context_kind: u8,
    ctx: &mut CompileCtx,
    tolerant: bool,
    partial_format_drops: &mut Vec<String>,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
    allowed_formats: Option<&BTreeSet<String>>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    compile_formats_reporting_with_nested_calldata_enrollments(
        display,
        context_kind,
        ctx,
        tolerant,
        partial_format_drops,
        interpolation_deployment,
        allowed_formats,
        &BTreeSet::new(),
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

/// Best-effort, diagnostics-only compilation of a format excluded by an
/// authenticated deployment allowlist.
///
/// Every mutable compiler input is isolated from the authoritative build:
/// this probe gets a cloned context, a fresh IR pool, fresh enum offsets, and
/// a throw-away output buffer. A successful probe emits no diagnostic and
/// grants no authority. A rejected probe lets the review receipt preserve the
/// deeper compiler reason that the policy exclusion would otherwise mask.
#[allow(clippy::too_many_arguments)]
fn diagnose_allowlist_excluded_format(
    sig: &str,
    fmt: &Format,
    display: &Display,
    context_kind: u8,
    ctx: &CompileCtx,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Option<String> {
    if let Some(key) = fmt
        .unknown
        .keys()
        .next()
        .cloned()
        .or_else(|| first_unmodeled_field_key(&fmt.fields))
    {
        return Some(format!(
            "format `{sig}`: unmodeled descriptor key `{key}` — dbgen does not act on it and \
             would silently drop it; refusing (finding 1.3)"
        ));
    }

    let resolved = match resolve_display_refs(&fmt.fields, display.definitions.as_ref()) {
        Ok(resolved) => resolved,
        Err(error) => return Some(format!("format `{sig}`: {error}")),
    };
    let fields = match flatten_field_groups(&resolved) {
        Ok(fields) => fields,
        Err(error) => return Some(format!("format `{sig}`: {error}")),
    };
    let flat = Format {
        _id: fmt._id.clone(),
        intent: fmt.intent.clone(),
        fields,
        interpolated_intent: fmt.interpolated_intent.clone(),
        unknown: BTreeMap::new(),
    };

    let mut scratch_ctx = ctx.clone();
    let mut scratch_pool = Pool::new();
    let mut enum_offsets: BTreeMap<String, u16> = BTreeMap::new();
    for field in &flat.fields {
        let Some(params) = &field.params else {
            continue;
        };
        let Some(refstr) = params
            .get("$ref")
            .and_then(|value| value.as_str())
            .or_else(|| params.get("ref").and_then(|value| value.as_str()))
        else {
            continue;
        };
        let Some(name) = refstr.strip_prefix("$.metadata.enums.") else {
            continue;
        };
        if enum_offsets.contains_key(name) {
            continue;
        }
        let offset = scratch_ctx
            .enums
            .get(name)
            .ok_or_else(|| format!("enum `{name}` referenced but not defined"))
            .and_then(|table| {
                encode_enum_table(table).map_err(|error| format!("enum `{name}` encoding: {error}"))
            })
            .and_then(|encoded| scratch_pool.push_raw(&encoded));
        match offset {
            Ok(offset) => {
                enum_offsets.insert(name.to_string(), offset);
            }
            Err(error) => return Some(error),
        }
    }

    let mut scratch_output = Vec::new();
    compile_one_format_with_nested_calldata_enrollments(
        sig,
        &flat,
        context_kind,
        &mut scratch_ctx,
        &mut scratch_pool,
        &enum_offsets,
        &mut scratch_output,
        interpolation_deployment,
        nested_calldata_enrollments,
    )
    .err()
}

#[allow(clippy::too_many_arguments)]
fn compile_formats_reporting_with_nested_calldata_enrollments(
    display: &Display,
    context_kind: u8,
    ctx: &mut CompileCtx,
    tolerant: bool,
    partial_format_drops: &mut Vec<String>,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
    allowed_formats: Option<&BTreeSet<String>>,
    refusal_only_formats: &BTreeSet<String>,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let n = display
        .formats
        .keys()
        .filter(|signature| {
            !refusal_only_formats.contains(*signature)
                && allowed_formats.is_none_or(|allowed| allowed.contains(*signature))
        })
        .count();
    // An explicit curation admission is an atomic reviewed set. Ordinary
    // unscoped descriptors retain the historical tolerant behavior, but an
    // admitted format may never disappear while sibling admissions still
    // acquire authority.
    let allow_partial_format_drops = tolerant && allowed_formats.is_none();
    if n == 0 {
        return Err(if allowed_formats.is_some() {
            "deploymentFormats selected no formats".to_string()
        } else {
            "display.formats is empty".to_string()
        });
    }
    if !allow_partial_format_drops && n > MAX_FORMATS {
        return Err(format!("format count {n} > MAX_FORMATS ({MAX_FORMATS})"));
    }

    let mut pool = Pool::new();

    // Flatten nested field GROUPS (ERC-7730 `fields` sub-arrays, e.g. Morpho's
    // `marketParams` tuple) into per-member leaf fields with combined paths
    // ONCE, up front, so the enum pre-pass AND the compile loop see identical
    // fields. A malformed group (no anchoring path / too deeply nested) drops
    // that one format in tolerant mode — exactly as a compile failure would —
    // and hard-errors in strict mode. See [`flatten_field_groups`].
    // Per-format blockers, surfaced in the "no compilable formats" skip reason
    // (review 1.4). Populated by BOTH the resolve/flatten pass here and the
    // compile loop below.
    let mut format_errs: Vec<String> = Vec::new();
    let mut flat: Vec<(&str, Format)> = Vec::with_capacity(n);
    for (sig, fmt) in display.formats.iter() {
        if refusal_only_formats.contains(sig) {
            let deployment = interpolation_deployment
                .map(|deployment| {
                    format!(
                        " for chain_id={} contract=0x{}",
                        deployment.chain_id,
                        hex::encode(deployment.contract)
                    )
                })
                .unwrap_or_default();
            format_errs.push(format!(
                "format `{sig}` excluded{deployment} by the authenticated PQSigner refusalOnlyFormats marker"
            ));
            continue;
        }
        if allowed_formats.is_some_and(|allowed| !allowed.contains(sig)) {
            let deployment = interpolation_deployment
                .map(|deployment| {
                    format!(
                        " for chain_id={} contract=0x{}",
                        deployment.chain_id,
                        hex::encode(deployment.contract)
                    )
                })
                .unwrap_or_default();
            let mut reason = format!(
                "format `{sig}` excluded{deployment} by the authenticated PQSigner deploymentFormats allowlist"
            );
            if let Some(error) = diagnose_allowlist_excluded_format(
                sig,
                fmt,
                display,
                context_kind,
                ctx,
                interpolation_deployment,
                nested_calldata_enrollments,
            ) {
                reason.push_str("; underlying compiler rejection: ");
                reason.push_str(&error);
            }
            format_errs.push(reason);
            continue;
        }
        // 1.3: an unmodelled top-level format/field key would be silently
        // dropped — exactly how `$ref` shipped degraded raw (finding 1.1).
        // Refuse the format instead of guessing. params SUB-keys are still
        // tolerated for forward-compat (a separate, narrower surface).
        if let Some(key) = fmt
            .unknown
            .keys()
            .next()
            .cloned()
            .or_else(|| first_unmodeled_field_key(&fmt.fields))
        {
            let msg = format!(
                "format `{sig}`: unmodeled descriptor key `{key}` — dbgen does not act on it and \
                 would silently drop it; refusing (finding 1.3)"
            );
            if allow_partial_format_drops {
                format_errs.push(msg);
                continue;
            }
            return Err(msg);
        }
        // Resolve field-level `$.display.definitions` `$ref`s BEFORE flatten +
        // compile, so the completeness lint and the field compiler both see the
        // referenced format/params (finding 1.1). Resolution failure drops the
        // one format to blind-sign in tolerant mode (recorded), hard-errors in
        // strict mode.
        let resolved = match resolve_display_refs(&fmt.fields, display.definitions.as_ref()) {
            Ok(r) => r,
            Err(e) if allow_partial_format_drops => {
                format_errs.push(format!("format `{sig}`: {e}"));
                continue;
            }
            Err(e) => return Err(format!("format `{sig}`: {e}")),
        };
        match flatten_field_groups(&resolved) {
            Ok(fields) => flat.push((
                sig.as_str(),
                Format {
                    _id: fmt._id.clone(),
                    intent: fmt.intent.clone(),
                    fields,
                    interpolated_intent: fmt.interpolated_intent.clone(),
                    unknown: BTreeMap::new(),
                },
            )),
            // Was a silent drop; record it so the skip report shows why.
            Err(e) if allow_partial_format_drops => {
                format_errs.push(format!("format `{sig}`: {e}"))
            }
            Err(e) => return Err(format!("format `{sig}`: {e}")),
        }
    }

    // Pre-intern referenced enum tables so $ref resolution can emit pool
    // offsets without re-walking. In tolerant mode a bad / undefined enum is
    // skipped here (the format(s) referencing it then fail to compile and are
    // themselves skipped below); strict mode hard-errors.
    let mut enum_offsets: BTreeMap<String, u16> = BTreeMap::new();
    for (_sig, fmt) in flat.iter() {
        for field in &fmt.fields {
            let Some(params) = &field.params else {
                continue;
            };
            let Some(refstr) = params
                .get("$ref")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("ref").and_then(|v| v.as_str()))
            else {
                continue;
            };
            let Some(name) = refstr.strip_prefix("$.metadata.enums.") else {
                continue;
            };
            if enum_offsets.contains_key(name) {
                continue;
            }
            let encoded = match ctx
                .enums
                .get(name)
                .ok_or_else(|| format!("enum `{name}` referenced but not defined"))
                .and_then(|table| {
                    encode_enum_table(table).map_err(|e| format!("enum `{name}` encoding: {e}"))
                }) {
                Ok(enc) => enc,
                Err(_) if allow_partial_format_drops => continue,
                Err(e) => return Err(e),
            };
            let off = pool.push_raw(&encoded)?;
            enum_offsets.insert(name.to_string(), off);
        }
    }

    // Compile each format. Tolerant mode keeps the compilable formats and
    // SKIPS the rest — a partially-supported descriptor (e.g. an aggregator
    // whose `approve` compiles but whose dynamic `swap` does not) still
    // clear-signs its renderable functions; every dropped contract selector
    // remains in the independent known-call omission filter and therefore
    // hard-refuses if the companion withholds a descriptor. Strict mode
    // `?`-fails the whole descriptor on the first bad format.
    let mut survivors: Vec<Vec<u8>> = Vec::with_capacity(n);
    for &(sig, ref fmt) in flat.iter() {
        if allow_partial_format_drops && survivors.len() >= MAX_FORMATS {
            format_errs.push(format!(
                "format `{sig}`: omitted because the descriptor already emitted MAX_FORMATS ({MAX_FORMATS}) safe formats"
            ));
            continue;
        }
        let mut one: Vec<u8> = Vec::new();
        match compile_one_format_with_nested_calldata_enrollments(
            sig,
            fmt,
            context_kind,
            ctx,
            &mut pool,
            &enum_offsets,
            &mut one,
            interpolation_deployment,
            nested_calldata_enrollments,
        ) {
            Ok(()) => survivors.push(one),
            Err(e) if allow_partial_format_drops => {
                format_errs.push(format!("format `{sig}`: {e}"));
            }
            Err(e) => return Err(e),
        }
    }

    if survivors.is_empty() {
        return Err(if format_errs.is_empty() {
            "no compilable formats in descriptor".to_string()
        } else {
            format!(
                "no compilable formats in descriptor — {}",
                format_errs.join("; ")
            )
        });
    }

    // [count][format…] — count is the SURVIVOR count (== n in strict mode, so
    // the strict catalog is byte-identical).
    let body_len: usize = survivors.iter().map(Vec::len).sum();
    let mut formats_buf: Vec<u8> = Vec::with_capacity(1 + body_len);
    formats_buf.push(survivors.len() as u8);
    for one in &survivors {
        formats_buf.extend_from_slice(one);
    }

    partial_format_drops.extend(format_errs);

    Ok((formats_buf, pool.into_bytes()))
}

/// Maximum nesting depth for ERC-7730 field GROUPS (`fields` sub-arrays).
/// Morpho's `marketParams` is one level; a real descriptor never needs many.
/// Bounding the recursion keeps a pathological (or hostile) descriptor from
/// blowing the host stack during flattening.
const MAX_FIELD_GROUP_DEPTH: usize = 4;

/// Resolve field-level `$ref` references into `$.display.definitions.*`
/// (ERC-7730 v2 `#/$display/reference`), recursively — including refs nested
/// inside a struct-display field GROUP. Merge rule (per the v2 schema + spec
/// prose, cross-checked against the 1inch / paraswap corpus):
///   - `format`   — ALWAYS from the definition (a reference object cannot
///                  carry `format`);
///   - `label`/`visible` — field-local if present, else the definition's;
///   - `params`   — per-key deep-merge with the reference winning
///                  (`merge_descriptors(def, field)`): e.g. a `tokenAmount`
///                  definition contributes `nativeCurrencyAddress` while the
///                  field contributes `tokenPath` — both must survive;
///   - `path`/`value` — from the reference object.
/// One level only: the schema forbids a definition from itself carrying a
/// display `$ref`, so a transitive ref hard-errors rather than recursing.
///
/// Unresolvable refs (missing definition) and non-`$.display.definitions`
/// field-level refs hard-error — the pre-fix behaviour silently dropped the
/// `$ref` key, defaulting the field to unlabeled `raw` and discarding its
/// `tokenPath`, so a labeled DEX-swap leg rendered as a blank 64-hex dump
/// under a trusted "Swap" banner (review finding 1.1). Fail loud instead.
fn resolve_display_refs(
    fields: &[FieldDef],
    defs: Option<&BTreeMap<String, FieldDef>>,
) -> Result<Vec<FieldDef>, String> {
    const REF_PREFIX: &str = "$.display.definitions.";
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        // GROUP node (struct/tuple display): recurse into children, keep the
        // group's own path/label. Schema makes group and reference mutually
        // exclusive; guard anyway.
        if let Some(children) = &field.fields {
            if field.ref_def.is_some() {
                return Err("field is both a `$ref` and a field group".to_string());
            }
            let resolved_children = resolve_display_refs(children, defs)?;
            let mut g = field.clone();
            g.fields = Some(resolved_children);
            out.push(g);
            continue;
        }
        let Some(refstr) = &field.ref_def else {
            out.push(field.clone());
            continue;
        };
        // A field-level `$ref` must target a display definition. (Enum refs
        // live in `params.$ref` = `$.metadata.enums.*` and are resolved by the
        // separate enum pre-intern pass; a field-level ref there is malformed.)
        let name = refstr.strip_prefix(REF_PREFIX).ok_or_else(|| {
            format!(
                "field `$ref: \"{refstr}\"` is not a `$.display.definitions.*` reference \
                 (only display-definition refs are supported at the field level)"
            )
        })?;
        let def = defs.and_then(|d| d.get(name)).ok_or_else(|| {
            format!("unresolved $ref `{refstr}` — no such display definition `{name}`")
        })?;
        if def.ref_def.is_some() {
            return Err(format!(
                "display definition `{name}` itself carries a `$ref` — transitive \
                 display-definition references are not permitted"
            ));
        }
        // 1.3 parity through the definitions ingress: the format-level gate in
        // `compile_formats` scans the reference OBJECT and inline fields, but a
        // definition BODY is only seen here. An unmodelled key on the definition
        // would otherwise be silently discarded on merge (`unknown` is zeroed
        // below) — reopening the exact silent-drop class (a def-carried
        // `encryption` would render ciphertext as plaintext under a verified
        // banner). Gate it here, matching the inline-field treatment. (finding
        // 1.3 definitions-body bypass, verify pass 2026-07-02)
        if let Some(k) = def.unknown.keys().next() {
            return Err(format!(
                "display definition `{name}` carries unmodeled key `{k}` — dbgen does not \
                 act on it and would silently drop it via the $ref merge; refusing (finding 1.3)"
            ));
        }
        if let Some(children) = &def.fields {
            if let Some(k) = first_unmodeled_field_key(children) {
                return Err(format!(
                    "display definition `{name}` group carries unmodeled key `{k}` — refusing (finding 1.3)"
                ));
            }
        }
        let params = match (def.params.clone(), field.params.clone()) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(merge_descriptors(b, o)),
        };
        out.push(FieldDef {
            path: field.path.clone(),
            value: field.value.clone(),
            label: field.label.clone().or_else(|| def.label.clone()),
            format: def.format.clone(),
            params,
            visible: field.visible.clone().or_else(|| def.visible.clone()),
            ref_def: None,
            // Definitions are leaf format specs; carry a group definition
            // through if one ever appears (flatten then expands it).
            fields: def.fields.clone(),
            _id: None,
            // Cosmetic separator: reference-local else definition (unemitted).
            _separator: field._separator.clone().or_else(|| def._separator.clone()),
            unknown: BTreeMap::new(),
        });
    }
    Ok(out)
}

/// Expand ERC-7730 nested field GROUPS into a flat field list with combined
/// paths. A field that carries a non-empty `fields` sub-array is a GROUP: its
/// own `path` (e.g. `#.marketParams`) prefixes each child's relative `path`
/// (e.g. `loanToken`) → `#.marketParams.loanToken`, recursively; leaf fields
/// pass through unchanged (with `fields` cleared).
///
/// This is purely syntactic path rewriting. The combined paths are compiled by
/// the SAME width-aware [`compile_structured_contract_path`] and filtered by the
/// SAME completeness / visibility / two-level-descent gates as a hand-authored
/// flat path, so flattening can only PRODUCE candidate paths — it bypasses no
/// safety gate. A group over a dynamic tuple / array / more than two levels
/// compiles to a path the existing gates reject, so the whole format drops to
/// loud blind-sign (tolerant corpus) rather than mis-rendering. Running it once
/// up front means the enum pre-pass and the compile loop see identical fields.
fn flatten_field_groups(fields: &[FieldDef]) -> Result<Vec<FieldDef>, String> {
    let mut out = Vec::with_capacity(fields.len());
    flatten_field_groups_into(fields, None, 0, &mut out)?;
    Ok(out)
}

fn flatten_field_groups_into(
    fields: &[FieldDef],
    prefix: Option<&str>,
    depth: usize,
    out: &mut Vec<FieldDef>,
) -> Result<(), String> {
    if depth > MAX_FIELD_GROUP_DEPTH {
        return Err(format!(
            "field group nesting exceeds MAX_FIELD_GROUP_DEPTH ({MAX_FIELD_GROUP_DEPTH})"
        ));
    }
    for field in fields {
        let combined = combine_field_path(prefix, field.path.as_deref());
        match field.fields.as_deref() {
            Some(children) if !children.is_empty() => {
                // GROUP node: must carry a `path` to anchor its children (a
                // group with no path has nothing for the members to be relative
                // to). It contributes no leaf itself.
                let group_prefix = combined.ok_or_else(|| {
                    "field group has a `fields` sub-array but no `path` to anchor its members"
                        .to_string()
                })?;
                flatten_field_groups_into(children, Some(&group_prefix), depth + 1, out)?;
            }
            _ => {
                // Leaf field: emit a copy carrying the combined path, no
                // sub-`fields`. Everything else (format/params/label/visible/
                // value) is preserved verbatim.
                let mut leaf = field.clone();
                leaf.path = combined;
                leaf.fields = None;
                out.push(leaf);
            }
        }
    }
    Ok(())
}

/// Combine a group `prefix` path with a child's relative `path`.
/// `#.marketParams` + `loanToken` → `#.marketParams.loanToken`. A child that
/// is itself absolute (`#`/`@`/`$`) is taken verbatim (spec-noncompliant under
/// a group, but we never fabricate a nonsensical double-rooted path); a leading
/// `.` on the child is absorbed.
fn combine_field_path(prefix: Option<&str>, child: Option<&str>) -> Option<String> {
    match (prefix, child) {
        (None, c) => c.map(str::to_string),
        (Some(p), None) => Some(p.to_string()),
        (Some(p), Some(c)) => {
            let c = c.trim();
            if c.starts_with('#') || c.starts_with('@') || c.starts_with('$') {
                Some(c.to_string())
            } else {
                Some(format!(
                    "{}.{}",
                    p.trim_end_matches('.'),
                    c.trim_start_matches('.')
                ))
            }
        }
    }
}

/// Compile the first fail-closed `interpolatedIntent` subset.
///
/// Source braces are consumed only here on the host. Each placeholder must
/// name exactly one post-`$ref`, post-group-flattening field path and is encoded
/// as that emitted field ordinal. Unsupported-but-valid presentation shapes
/// return `Ok(None)` so the independently safe static `intent` remains in use;
/// malformed or ambiguous amount templates return `Err` and cannot enter the
/// authenticated catalogue.
fn compile_interpolated_intent(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &CompileCtx,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(template) = fmt.interpolated_intent.as_deref() else {
        return Ok(None);
    };

    // v1 is contract-calldata only. EIP-712 nested/array witness semantics are
    // a later bounded slice; those descriptors keep their static intent.
    if context_kind != CTX_CONTRACT {
        return Ok(None);
    }
    // The renderer already has an independently derived exact-zero ERC-20
    // revoke title. Avoid two authenticated banner authorities for the whole
    // selector class, including a different textual signature that collides
    // with `approve(address,uint256)`. Device validation applies this exact
    // selector policy too; comparing source text here would be weaker.
    let computed_selector_hash = keccak256(parsed.types_signature.as_bytes());
    let computed_selector = [
        computed_selector_hash[0],
        computed_selector_hash[1],
        computed_selector_hash[2],
        computed_selector_hash[3],
    ];
    if computed_selector == ERC20_APPROVE_SELECTOR {
        return Ok(None);
    }
    if template.is_empty()
        || template.len() > MAX_POOL_TLV_PAYLOAD
        || !template.bytes().all(|b| (0x20..0x7f).contains(&b))
    {
        return Ok(None);
    }
    if template.starts_with(' ') || template.ends_with(' ') {
        return Err(format!(
            "format `{sig}` interpolatedIntent has ambiguous leading/trailing display padding"
        ));
    }

    let bytes = template.as_bytes();
    let mut literals: Vec<Vec<u8>> = Vec::new();
    let mut ordinals: Vec<u8> = Vec::new();
    let mut literal_start = 0usize;
    let mut cursor = 0usize;
    let mut token_amount_refs = 0usize;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'}' => {
                return Err(format!(
                    "format `{sig}` interpolatedIntent has an unmatched `}}`"
                ))
            }
            b'{' => {
                literals.push(bytes[literal_start..cursor].to_vec());
                let placeholder_start = cursor + 1;
                let rel_close = bytes[placeholder_start..]
                    .iter()
                    .position(|&b| b == b'}')
                    .ok_or_else(|| {
                        format!("format `{sig}` interpolatedIntent has an unmatched `{{`")
                    })?;
                let close = placeholder_start + rel_close;
                let placeholder = &template[placeholder_start..close];
                if placeholder.is_empty()
                    || placeholder.starts_with(' ')
                    || placeholder.ends_with(' ')
                    || placeholder.as_bytes().contains(&b'{')
                {
                    return Err(format!(
                        "format `{sig}` interpolatedIntent has an empty, nested, or padded placeholder"
                    ));
                }
                if ordinals.len() == MAX_INTERPOLATED_SUBSTITUTIONS {
                    return Err(format!(
                        "format `{sig}` interpolatedIntent exceeds {MAX_INTERPOLATED_SUBSTITUTIONS} substitutions"
                    ));
                }

                let mut matching = fmt.fields.iter().enumerate().filter(|(_, field)| {
                    field
                        .path
                        .as_deref()
                        .is_some_and(|path| interpolation_paths_match(path, placeholder))
                });
                let Some((field_index, field)) = matching.next() else {
                    // Registry v2 explicitly permits falling back to the
                    // static intent when interpolation cannot be resolved.
                    // Do so at build time rather than dropping an otherwise
                    // safe format from the authenticated catalogue.
                    return Ok(None);
                };
                if matching.next().is_some() {
                    return Err(format!(
                        "format `{sig}` interpolatedIntent placeholder `{{{placeholder}}}` is ambiguous"
                    ));
                }
                let field_ordinal = u8::try_from(field_index)
                    .map_err(|_| format!("format `{sig}` interpolation field index overflow"))?;
                if ordinals.contains(&field_ordinal) {
                    return Err(format!(
                        "format `{sig}` interpolatedIntent repeats field `{{{placeholder}}}`"
                    ));
                }
                match field.visible.as_deref() {
                    None | Some("always") => {}
                    _ => {
                        return Err(format!(
                            "format `{sig}` interpolatedIntent references non-always-visible field `{{{placeholder}}}`"
                        ))
                    }
                }

                let format_op = parse_format_name(field.format.as_deref().unwrap_or("raw"))?;
                if !matches!(format_op, FMT_AMOUNT | FMT_TOKEN_AMOUNT) {
                    // Valid upstream address/NFT/raw summaries are outside the
                    // scalar amount witness subset; retain the static intent.
                    return Ok(None);
                }
                if field
                    .params
                    .as_ref()
                    .and_then(|p| p.as_object())
                    .is_some_and(|p| p.contains_key("threshold") || p.contains_key("message"))
                {
                    // Threshold/message output is semantic shorthand, not the
                    // canonical numeric witness required by interpolation v1.
                    return Ok(None);
                }
                if format_op == FMT_TOKEN_AMOUNT {
                    token_amount_refs += 1;
                    if token_amount_refs > 1 {
                        // The current request envelope supplies at most one
                        // authenticated ERC-20 metadata entry.
                        return Ok(None);
                    }
                    if !token_amount_interpolation_identity_is_authenticated(
                        field,
                        context_kind,
                        parsed,
                        ctx,
                        interpolation_deployment,
                    )? {
                        // The ordinary field remains fully rendered and the
                        // descriptor's static intent remains authenticated.
                        // Only the stronger value-bearing banner authority is
                        // omitted when its ticker/scale witness is not known
                        // to exist for this exact deployment.
                        return Ok(None);
                    }
                }

                let path = field.path.as_deref().unwrap_or("");
                if path.starts_with('@') || path.starts_with('$') {
                    return Ok(None);
                }
                let terminal = rendered_path_terminal_type(path, context_kind, parsed)?
                    .ok_or_else(|| format!("format `{sig}` interpolation path has no ABI type"))?;
                let (base, is_array) = split_array_suffix(&terminal);
                let unsigned_integer = base.strip_prefix("uint").is_some_and(|width| {
                    width.is_empty() || width.bytes().all(|b| b.is_ascii_digit())
                });
                if is_array || !unsigned_integer {
                    return Ok(None);
                }

                ordinals.push(field_ordinal);
                cursor = close + 1;
                literal_start = cursor;
            }
            _ => cursor += 1,
        }
    }
    literals.push(bytes[literal_start..].to_vec());

    if ordinals.is_empty() {
        return Ok(None);
    }
    // PQ1 substitutes the formatter's trusted-display witness, including its
    // authenticated unit/ticker. Ambire's companion renderer instead inserts
    // a raw decoded integer, so upstream templates sometimes append a unit in
    // the following literal (for example `{amount} BORG`). Enroll only one
    // terminal scalar in this first device slice: this prevents duplicated or
    // contradictory unit copy while retaining the ordinary field and token-
    // identity pages. The v1 bytecode stays bounded for a later reviewed
    // multi-value expansion.
    if ordinals.len() != 1 || !literals.last().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    let literal_total = literals
        .iter()
        .try_fold(0usize, |total, literal| total.checked_add(literal.len()));
    let Some(literal_total) = literal_total else {
        return Ok(None);
    };
    // Every exact amount witness is at least one visible byte. If even that
    // lower bound cannot fit two OLED rows, this template can never render.
    if literal_total + ordinals.len() > MAX_INTERPOLATED_INTENT_LEN {
        return Ok(None);
    }

    let mut program = Vec::new();
    program.push(INTERPOLATED_INTENT_VERSION);
    program.push(ordinals.len() as u8);
    for (literal, ordinal) in literals.iter().take(ordinals.len()).zip(&ordinals) {
        program.push(literal.len() as u8);
        program.extend_from_slice(literal);
        program.push(*ordinal);
    }
    let final_literal = literals
        .last()
        .expect("one final literal is always pushed above");
    program.push(final_literal.len() as u8);
    program.extend_from_slice(final_literal);
    if program.len() > MAX_POOL_TLV_PAYLOAD {
        return Ok(None);
    }
    Ok(Some(program))
}

/// Prove that a `tokenAmount` interpolation has a deployment-static token
/// identity and an authenticated magnitude/unit witness.
///
/// Runtime calldata paths are intentionally ineligible even if the current
/// ERC-20 corpus contains some possible token: enrollment must hold for every
/// transaction accepted by the descriptor. `@.to` is the sole static path and
/// is compared in compiled wire space against the same constant the device
/// accepts. A literal/constant `token` is also static. In either case the exact
/// `(chain, token)` must exist in the validated ERC-20 DB, unless the token is
/// a descriptor-pinned native sentinel on a chain whose native ticker/18-decimal
/// scale is firmware-pinned already.
fn token_amount_interpolation_identity_is_authenticated(
    field: &FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &CompileCtx,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
) -> Result<bool, String> {
    let Some(deployment) = interpolation_deployment else {
        return Ok(false);
    };
    let Some(params) = field.params.as_ref().and_then(|params| params.as_object()) else {
        return Ok(false);
    };

    // Device precedence is tokenPath first, then token literal. Mirror it so a
    // dynamic path cannot borrow enrollment authority from a dormant literal.
    let token = if let Some(token_path) = params.get("tokenPath") {
        let token_path = token_path
            .as_str()
            .ok_or_else(|| "tokenAmount.tokenPath must be a string".to_string())?;
        let program = compile_token_path(token_path, context_kind, parsed)
            .map_err(|e| format!("tokenPath `{token_path}`: {e}"))?;
        if program.as_slice() != NFT_COLLECTION_TO_PATH.as_slice() {
            return Ok(false);
        }
        deployment.contract
    } else if let Some(token) = params.get("token") {
        let token = token
            .as_str()
            .ok_or_else(|| "tokenAmount.token must be a string".to_string())?;
        resolve_address_or_const(token, ctx)?
    } else {
        return Ok(false);
    };

    if deployment
        .erc20_capabilities
        .contains(deployment.chain_id, &token)
    {
        return Ok(true);
    }

    if known_native_ticker(deployment.chain_id).is_none() {
        return Ok(false);
    }
    let Some(native_currency) = params.get("nativeCurrencyAddress") else {
        return Ok(false);
    };
    let native_addresses = compile_native_currency_addresses(native_currency, ctx)?;
    Ok(native_addresses
        .chunks_exact(pqsigner_erc7730::render::params::NATIVE_CURRENCY_ADDRESS_LEN)
        .any(|candidate| candidate == token))
}

/// ERC-7730 calldata examples use both root-explicit (`#.amount`) and
/// root-relative (`amount`) placeholder spellings for a field whose emitted
/// path is `#.amount`. Treat exactly that optional structured-root prefix as
/// equivalent; no trimming, case folding, or broader path normalization is
/// permitted. If both spellings are emitted as distinct fields, the caller's
/// ambiguity check rejects enrollment.
fn interpolation_paths_match(field_path: &str, placeholder: &str) -> bool {
    field_path == placeholder
        || field_path.strip_prefix("#.") == Some(placeholder)
        || placeholder.strip_prefix("#.") == Some(field_path)
}

#[cfg(test)]
fn compile_one_format(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    out: &mut Vec<u8>,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
) -> Result<(), String> {
    compile_one_format_with_nested_calldata_enrollments(
        sig,
        fmt,
        context_kind,
        ctx,
        pool,
        enum_offsets,
        out,
        interpolation_deployment,
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_one_format_with_nested_calldata_enrollments(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    out: &mut Vec<u8>,
    interpolation_deployment: Option<&InterpolationDeployment<'_>>,
    nested_calldata_enrollments: &[NestedCalldataEnrollment],
) -> Result<(), String> {
    let parsed = parse_format_key(sig).map_err(|e| format!("format `{sig}`: {e}"))?;
    let canonical_contract_signature = if context_kind == CTX_CONTRACT {
        let canonical = contract_selector_signature(sig)?;
        if canonical != parsed.types_signature {
            return Err(format!(
                "format `{sig}` selector parser disagreement: canonical `{canonical}` vs renderer `{}`",
                parsed.types_signature
            ));
        }
        Some(canonical)
    } else {
        None
    };

    // Derive the complete multi-tail topology from the canonical signature,
    // never from descriptor visibility or the subset of fields that happen to
    // render. The authenticated field-zero marker lets runtime prove one exact
    // ordered partition of every tail byte before any trusted page is painted.
    // Static and sole-tail formats deliberately emit no marker and retain their
    // byte-identical legacy interpretation.
    let dynamic_tail_topology = if context_kind == CTX_CONTRACT {
        derive_dynamic_tail_topology(&parsed).map_err(|error| format!("format `{sig}`: {error}"))?
    } else {
        None
    };

    // Audit H-3: refuse to pin a contract-context descriptor that leaves
    // any calldata argument unaccounted for. The on-device renderer can't
    // reconstruct ABI arity, so completeness is enforced here — where the
    // full signature is known — at build time.
    if context_kind == CTX_CONTRACT {
        check_contract_field_completeness(sig, fmt, &parsed)?;
    } else {
        // Audit 2026-06-25 HIGH-1: the typed-data sibling of H-3. Every
        // EIP-712 member is folded into the signed `structHash =
        // keccak(primary_type_hash || encoded_data)`, and each top-level
        // member occupies exactly one head word (struct refs and dynamic
        // types hash to a single word). The on-device exact-length gate
        // forces `encoded_data` to the full member arity but does NOT check
        // that every word reaches a page, so an under-declared descriptor
        // could sign an effect-bearing member (e.g. a Permit2 `spender`)
        // that the trusted display never shows. Enforce per-member coverage
        // here at build time, exactly as the contract path does.
        check_eip712_field_completeness(sig, fmt, &parsed)?;
    }

    // WYSIWYS visibility gate (`VULN-erc7730-visible-never-noparam-
    // clearsign`). Completeness above only proves every argument is
    // *declared* (rendered OR `visible:"never"`); it deliberately blesses an
    // explicit hide. This gate proves the effect-bearing arguments are
    // *shown* — refusing a format that surfaces NONE of its arguments, or
    // that hides a fund-routing `address` behind a trusted clear-sign. A
    // refused format drops to loud blind-sign (tolerant corpus) or hard-
    // errors a hand-authored strict descriptor so we fix it — never a
    // reassuring parameter-less clear-sign.
    check_field_visibility(sig, fmt, &parsed, context_kind)?;

    // A nested EIP-712 struct's top-level encodeData word is its hashStruct,
    // but clear-signing expands that commitment into member pages. Once the
    // ordinary visibility rules have accepted the format, require every
    // elementary nested member to be declared at its exact path. Keeping this
    // after the visibility gate preserves the established first-error receipts
    // for corpus formats that were already refused for an explicit hide, while
    // ensuring no otherwise-eligible partial nested display can be pinned.
    let mut nested_rank_refusal = false;
    if context_kind == CTX_EIP712 {
        match check_eip712_nested_field_completeness(sig, fmt, &parsed) {
            Ok(()) => {}
            Err(NestedCompletenessError::UnsupportedStructuredArrayRank(_)) => {
                // Preserve the build-time rank rejection as a typed outcome,
                // then emit only the device's canonical hard-refusal marker.
                // The independent lowerer must also reject the shape below.
                nested_rank_refusal = true;
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    // Selector / discriminator slot — 4 bytes. For EIP-712 we also keep
    // the FULL 32-byte primary-type hash so the on-device renderer can
    // bind all 32 bytes (audit M-5), not just the 4-byte prefix it
    // selects the display template by.
    let eip712_type_hash: Option<[u8; 32]> = if context_kind == CTX_CONTRACT {
        None
    } else {
        // The EIP-712 format key IS the typed-data `encodeType` string
        // (e.g. `Permit(address owner,address spender,uint256 value,
        // uint256 nonce,uint256 deadline)`); its keccak256 is the
        // primary-type hash the dapp/companion supplies at sign time.
        Some(keccak256(sig.as_bytes()))
    };
    let selector: [u8; 4] = if context_kind == CTX_CONTRACT {
        // Hash the independent canonical derivation after requiring it to
        // agree exactly with the renderer parser. A grammar discrepancy must
        // stay in the known-call refusal set without becoming an authenticated
        // leaf under a bogus selector.
        let canonical = canonical_contract_signature
            .as_deref()
            .expect("contract signature computed above");
        let h = keccak256(canonical.as_bytes());
        [h[0], h[1], h[2], h[3]]
    } else {
        let h = eip712_type_hash.expect("eip712 type hash computed above");
        [h[0], h[1], h[2], h[3]]
    };

    let semantic_enrollment = if context_kind == CTX_CONTRACT {
        semantic_enrollment_for(
            ctx.descriptor_hash,
            interpolation_deployment,
            canonical_contract_signature
                .as_deref()
                .expect("contract signature computed above"),
            selector,
        )
    } else {
        None
    };
    let exact_empty_bytes_enrollment = if context_kind == CTX_CONTRACT {
        exact_empty_bytes_enrollment_for(
            ctx.descriptor_hash,
            interpolation_deployment,
            canonical_contract_signature
                .as_deref()
                .expect("contract signature computed above"),
            selector,
        )
    } else {
        None
    };
    let nested_calldata_enrollment = if context_kind == CTX_CONTRACT {
        match interpolation_deployment {
            Some(deployment) => lookup_parent(
                nested_calldata_enrollments,
                NestedCalldataParentKey {
                    descriptor_hash: &ctx.descriptor_hash,
                    chain_id: deployment.chain_id,
                    parent_contract: &deployment.contract,
                    parent_selector: &selector,
                },
            )
            .map_err(|_| {
                format!("format `{sig}` has ambiguous nested-calldata semantic enrollments")
            })?,
            None => None,
        }
    } else {
        None
    };
    let eip712_string_preimage_enrollment = if context_kind == CTX_EIP712 {
        eip712_string_preimage_enrollment_for(
            ctx.descriptor_hash,
            interpolation_deployment,
            sig,
            eip712_type_hash.expect("EIP-712 type hash computed above"),
        )
    } else {
        None
    };
    let eip712_word_guard_required = context_kind == CTX_EIP712
        && (ctx.eip712_word_guard_source_required
            || eip712_word_guard_required_for(
                interpolation_deployment,
                sig,
                eip712_type_hash.expect("EIP-712 type hash computed above"),
            ));
    let eip712_word_guard_enrollment = if context_kind == CTX_EIP712 {
        eip712_word_guard_enrollment_for(
            ctx.descriptor_hash,
            interpolation_deployment,
            sig,
            eip712_type_hash.expect("EIP-712 type hash computed above"),
        )
    } else {
        None
    };
    if eip712_word_guard_required && eip712_word_guard_enrollment.is_none() {
        return Err(format!(
            "format `{sig}` requires an exact descriptor/deployment/type EIP-712 word-guard enrollment"
        ));
    }
    let string_preimage_count = match eip712_string_preimage_enrollment {
        Some(enrollment) => {
            validate_eip712_string_preimage_format_source(sig, fmt, &parsed, enrollment)?
        }
        None => 0,
    };
    if let Some(enrollment) = exact_empty_bytes_enrollment {
        validate_exact_empty_bytes_format_source(sig, fmt, &parsed, enrollment)?;
    }
    let declared_calldata_fields = fmt
        .fields
        .iter()
        .filter(|field| field.format.as_deref() == Some("calldata"))
        .count();
    if let Some(enrollment) = nested_calldata_enrollment {
        if declared_calldata_fields != 1 {
            return Err(format!(
                "format `{sig}` nested calldata requires exactly one matching descriptor/deployment/signature/selector enrollment and one calldata field"
            ));
        }
        validate_nested_calldata_format_source(sig, fmt, &parsed, enrollment)?;
    } else if declared_calldata_fields > 1 {
        return Err(format!(
            "format `{sig}` declares {declared_calldata_fields} calldata fields; exactly one is supported"
        ));
    }
    if format_declares_sender_address(fmt) && semantic_enrollment.is_none() {
        return Err(format!(
            "format `{sig}` declares senderAddress without an exact descriptor/deployment/selector semantic enrollment"
        ));
    }
    let declares_packed_v3_path = format_declares_packed_v3_path(fmt);
    let packed_v3_path_enrolled = semantic_enrollment.is_some_and(|entry| entry.packed_v3_path);
    if declares_packed_v3_path != packed_v3_path_enrolled {
        return Err(format!(
            "format `{sig}` packed V3 path formatter requires exactly one matching descriptor/deployment/signature/selector semantic enrollment"
        ));
    }
    if packed_v3_path_enrolled {
        validate_packed_v3_format_source(sig, fmt, &parsed)?;
    }

    // Sanity: field count.
    if fmt.fields.len() > MAX_FIELDS_PER_FORMAT {
        return Err(format!(
            "format `{sig}`: field count {} > MAX_FIELDS_PER_FORMAT ({MAX_FIELDS_PER_FORMAT})",
            fmt.fields.len()
        ));
    }

    let intent_raw = fmt.intent.as_deref().unwrap_or("Sign");
    let intent = clean_ascii_truncated(intent_raw, 254);
    if intent.is_empty() {
        return Err(format!(
            "format `{sig}`: empty / non-printable `intent` (was {intent_raw:?})"
        ));
    }

    // Static ABI head width — the device uses this to bound every field's
    // calldata read to the static head (defence-in-depth behind the
    // width-aware path slots; see `format_static_head_words`).
    let static_head_words = format_static_head_words(context_kind, &parsed)
        .map_err(|e| format!("format `{sig}`: {e}"))?;

    // On-device belt for `VULN-erc7730-eip712-nested-struct-address-hide`:
    // an EIP-712 primary type with a nested struct member carries an opaque
    // `hashStruct` word the device cannot expand. Flag it here (parked on the
    // first field, since the header schema has no spare byte) so the device
    // declines the whole format rather than partially clear-signing it,
    // painting a struct word as a garbage value, or authorizing fallback. The
    // build-time visibility gate above is the primary defense; this is the
    // defense-in-depth backstop. Only meaningful for EIP-712 (contract keys
    // have no `struct_defs`).
    let has_nested_struct = context_kind == CTX_EIP712
        && parsed.top_types.iter().any(|ty| {
            let (base, _) = split_array_suffix(ty);
            type_is_struct(base, &parsed)
        });

    // Compile every field's path + params first (so offsets are stable before
    // we emit the format header). An EIP-712 format with a nested-struct member
    // is restructured into the v0x03 recursive-IR shape — each supported nested
    // member becomes ONE anchor field carrying `PARAM_NESTED_STRUCT` with its
    // visible children as LOCAL sub-fields (Phase 5,
    // `docs/erc7730-nested-eip712-render-design.md`). An unsupported nested
    // shape (array / depth>1 / uncompilable child / uncovered address) falls
    // back to flat fields + the bare `[0x01]` belt marker so the device
    // refuses the whole format. `nested_descent_count` is the E1
    // reconciliation pin: the number of nested descent points the device MUST
    // bind, derived HERE (independent of the render traversal).
    let mut emitted_bare_nested_refusal = false;
    let (mut compiled, nested_descent_count): (Vec<CompiledFieldOut>, u8) = if has_nested_struct {
        match try_compile_eip712_nested(
            sig,
            fmt,
            &parsed,
            ctx,
            pool,
            enum_offsets,
            eip712_string_preimage_enrollment,
        )? {
            Some(_) if nested_rank_refusal => {
                return Err(format!(
                    "format `{sig}`: nested rank admission rejected the shape but the independent lowerer produced an active anchor"
                ));
            }
            Some(res) => res,
            None if nested_rank_refusal => {
                emitted_bare_nested_refusal = true;
                (compile_bare_nested_refusal(pool)?, 0)
            }
            None => (
                compile_flat_fields(
                    sig,
                    fmt,
                    context_kind,
                    &parsed,
                    ctx,
                    pool,
                    enum_offsets,
                    true,
                    false,
                    None,
                    eip712_string_preimage_enrollment,
                    None,
                )?,
                0,
            ),
        }
    } else {
        (
            compile_flat_fields(
                sig,
                fmt,
                context_kind,
                &parsed,
                ctx,
                pool,
                enum_offsets,
                false,
                packed_v3_path_enrolled,
                exact_empty_bytes_enrollment.map(|entry| entry.path),
                eip712_string_preimage_enrollment,
                nested_calldata_enrollment,
            )?,
            0,
        )
    };

    if let Some(enrollment) = semantic_enrollment {
        apply_semantic_enrollment(
            sig,
            fmt,
            context_kind,
            &parsed,
            ctx,
            pool,
            &mut compiled,
            enrollment,
        )?;
    }
    if let Some(enrollment) = eip712_word_guard_enrollment {
        validate_eip712_deployment_chain_guard(sig, enrollment)?;
        apply_word_guards(
            sig,
            fmt,
            context_kind,
            &parsed,
            pool,
            &mut compiled,
            enrollment.guards,
        )?;
    }

    // `interpolatedIntent` is presentation derived from values that keep their
    // ordinary field pages. The host resolves braces to final emitted field
    // ordinals; the device receives only a tiny authenticated token program.
    // Valid upstream shapes outside this first scalar-amount subset retain the
    // descriptor's static `intent` and emit no program. Once emitted, however,
    // runtime witness failure is fatal and can never fall back to static copy.
    if !emitted_bare_nested_refusal {
        if let Some(program) = compile_interpolated_intent(
            sig,
            fmt,
            context_kind,
            &parsed,
            ctx,
            interpolation_deployment,
        )? {
            let first = compiled
                .first_mut()
                .ok_or_else(|| format!("format `{sig}` interpolation has no emitted field"))?;
            first.param_off =
                pool.append_param_tlv(first.param_off, PARAM_INTERPOLATED_INTENT, &program)?;
        }
    }

    if let Some(topology) = dynamic_tail_topology {
        let first = compiled
            .first_mut()
            .ok_or_else(|| format!("format `{sig}` dynamic-tail topology has no emitted field"))?;
        first.param_off =
            pool.append_param_tlv(first.param_off, PARAM_DYNAMIC_TAIL_TOPOLOGY, &topology)?;
    }

    // Emit format header.
    out.extend_from_slice(&selector); // 4 B
    out.push(compiled.len() as u8); // 1 B field_count
    out.push(intent.len() as u8); // 1 B intent_len
    out.extend_from_slice(&static_head_words.to_be_bytes()); // 2 B static_head_words
                                                             // Schema v4: E1 reconciliation pin — the count of nested-EIP-712 struct
                                                             // descent points (`PARAM_NESTED_STRUCT` v0x03 anchors) the device MUST bind
                                                             // before signing. Independent of the render traversal, so a regression that
                                                             // makes descent conditional under-consumes and declines. `0` until the
                                                             // nested-anchor emission lands (next increment) and for every non-nested /
                                                             // contract format.
    out.push(nested_descent_count); // 1 B nested_descent_count
                                    // Schema v6: independently derived count of exact EIP-712 string-preimage
                                    // records. Contract and unenrolled formats always carry zero.
    out.push(string_preimage_count); // 1 B string_preimage_count
    out.extend_from_slice(intent.as_bytes()); // intent_len B
                                              // EIP-712 only: full 32-byte primary-type hash (audit M-5). Contract
                                              // formats omit this so their on-wire bytes are unchanged.
    if let Some(th) = eip712_type_hash {
        out.extend_from_slice(&th); // 32 B
    }

    // Emit fields.
    for cf in &compiled {
        out.push(cf.format_op); // 1 B
        out.push(cf.label.len() as u8); // 1 B
        out.extend_from_slice(&cf.label); // label_len B
        out.extend_from_slice(&cf.path_off.to_be_bytes()); // 2 B
        out.extend_from_slice(&cf.param_off.to_be_bytes()); // 2 B
    }

    Ok(())
}

#[derive(Debug)]
struct CompiledFieldOut {
    format_op: u8,
    label: Vec<u8>,
    path_off: u16,
    param_off: u16,
}

fn semantic_enrollment_for(
    descriptor_hash: [u8; 32],
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    selector: [u8; 4],
) -> Option<&'static SemanticFormatEnrollment> {
    let deployment = deployment?;
    SEMANTIC_FORMAT_ENROLLMENTS.iter().find(|entry| {
        entry.descriptor_hash == descriptor_hash
            && entry.chain_id == deployment.chain_id
            && entry.contract == deployment.contract
            && entry.canonical_signature == canonical_signature
            && entry.selector == selector
    })
}

fn exact_empty_bytes_enrollment_for(
    descriptor_hash: [u8; 32],
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    selector: [u8; 4],
) -> Option<&'static ExactEmptyBytesEnrollment> {
    let deployment = deployment?;
    EXACT_EMPTY_BYTES_ENROLLMENTS.iter().find(|entry| {
        entry.descriptor_hash == descriptor_hash
            && entry.chain_id == deployment.chain_id
            && entry.contract == deployment.contract
            && entry.canonical_signature == canonical_signature
            && entry.selector == selector
    })
}

fn eip712_string_preimage_enrollment_for(
    descriptor_hash: [u8; 32],
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    type_hash: [u8; 32],
) -> Option<&'static Eip712StringPreimageEnrollment> {
    eip712_string_preimage_enrollment_for_in(
        &EIP712_STRING_PREIMAGE_ENROLLMENTS,
        descriptor_hash,
        deployment,
        canonical_signature,
        type_hash,
    )
}

fn eip712_string_preimage_enrollment_for_in<'a>(
    enrollments: &'a [Eip712StringPreimageEnrollment],
    descriptor_hash: [u8; 32],
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    type_hash: [u8; 32],
) -> Option<&'a Eip712StringPreimageEnrollment> {
    let deployment = deployment?;
    enrollments.iter().find(|entry| {
        entry.descriptor_hash == descriptor_hash
            && entry.chain_id == deployment.chain_id
            && entry.contract == deployment.contract
            && entry.canonical_signature == canonical_signature
            && entry.type_hash == type_hash
    })
}

fn eip712_word_guard_enrollment_for(
    descriptor_hash: [u8; 32],
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    type_hash: [u8; 32],
) -> Option<&'static Eip712WordGuardEnrollment> {
    let deployment = deployment?;
    EIP712_WORD_GUARD_ENROLLMENTS.iter().find(|entry| {
        entry.descriptor_hash == descriptor_hash
            && entry.chain_id == deployment.chain_id
            && entry.contract == deployment.contract
            && entry.canonical_signature == canonical_signature
            && entry.type_hash == type_hash
    })
}

fn eip712_word_guard_source_required(path: &Path) -> bool {
    path.ends_with(Path::new(LOMBARD_FEE_APPROVAL_SOURCE_SUFFIX))
}

/// Return true when this deployment/type has contract semantics that require a
/// signed-word predicate. Descriptor-hash drift must refuse instead of
/// compiling the same semantic identity without its reviewed guard.
fn eip712_word_guard_required_for(
    deployment: Option<&InterpolationDeployment<'_>>,
    canonical_signature: &str,
    type_hash: [u8; 32],
) -> bool {
    let Some(deployment) = deployment else {
        return false;
    };
    EIP712_WORD_GUARD_ENROLLMENTS.iter().any(|entry| {
        entry.chain_id == deployment.chain_id
            && entry.contract == deployment.contract
            && entry.canonical_signature == canonical_signature
            && entry.type_hash == type_hash
    })
}

/// Re-derive the source authority represented by a string-preimage enrollment.
/// The enrollment identity lookup deliberately does not suffice on its own:
/// this pass pins the exact dynamic-string field set, descriptor traversal
/// order, effective visibility, formatter, top-level member type, and static
/// EIP-712 word path. It returns the independently counted header pin.
fn validate_eip712_string_preimage_format_source(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    enrollment: &Eip712StringPreimageEnrollment,
) -> Result<u8, String> {
    if enrollment.fields.is_empty() || enrollment.fields.len() > MAX_EIP712_STRING_PREIMAGES {
        return Err(format!(
            "format `{sig}` string-preimage enrollment count {} is outside 1..={MAX_EIP712_STRING_PREIMAGES}",
            enrollment.fields.len()
        ));
    }
    if keccak256(sig.as_bytes()) != enrollment.type_hash {
        return Err(format!(
            "format `{sig}` string-preimage enrollment typehash does not match the exact encodeType"
        ));
    }
    for (expected, field) in enrollment.fields.iter().enumerate() {
        if usize::from(field.ordinal) != expected {
            return Err(format!(
                "format `{sig}` string-preimage enrollment ordinals must be canonical 0..count in field traversal order"
            ));
        }
    }

    // Derive the complete source string set without consulting the enrollment
    // paths. This catches added, removed, duplicated, reordered, hidden, and
    // nested string fields before any marker can be emitted.
    let mut derived: Vec<(usize, &str)> = Vec::new();
    for (field_idx, field) in fmt.fields.iter().enumerate() {
        let Some(path) = field.path.as_deref() else {
            continue;
        };
        if rendered_path_terminal_type(path, CTX_EIP712, parsed)?.as_deref() == Some("string") {
            derived.push((field_idx, path));
        }
    }
    let enrolled_paths: Vec<_> = enrollment.fields.iter().map(|field| field.path).collect();
    let derived_paths: Vec<_> = derived.iter().map(|(_, path)| *path).collect();
    if derived_paths != enrolled_paths {
        return Err(format!(
            "format `{sig}` string-preimage source field set/order drift: expected {enrolled_paths:?}, got {derived_paths:?}"
        ));
    }

    for ((field_idx, path), enrolled) in derived.iter().zip(enrollment.fields) {
        let field = &fmt.fields[*field_idx];
        if *path != enrolled.path {
            return Err(format!(
                "format `{sig}` string-preimage field order drift at ordinal {}",
                enrolled.ordinal
            ));
        }
        if field.format.as_deref() != Some("raw") {
            return Err(format!(
                "format `{sig}` string-preimage field `{path}` must explicitly use raw format"
            ));
        }
        if !matches!(field.visible.as_deref(), None | Some("always")) {
            return Err(format!(
                "format `{sig}` string-preimage field `{path}` must be visible always"
            ));
        }
        let member_ordinal = parsed
            .top_names
            .iter()
            .position(|name| name == path)
            .ok_or_else(|| {
                format!(
                    "format `{sig}` string-preimage field `{path}` is not a direct top-level member"
                )
            })?;
        if parsed.top_types.get(member_ordinal).map(String::as_str) != Some("string") {
            return Err(format!(
                "format `{sig}` string-preimage field `{path}` terminal type is not exactly string"
            ));
        }
        let member_ordinal = u16::try_from(member_ordinal)
            .map_err(|_| format!("format `{sig}` has too many top-level members"))?;
        let expected_path = [
            PATHOP_ROOT_STRUCT,
            PATHOP_FIELD_IDX,
            (member_ordinal >> 8) as u8,
            member_ordinal as u8,
        ];
        if compile_path(path, CTX_EIP712, parsed)?.as_slice() != expected_path {
            return Err(format!(
                "format `{sig}` string-preimage field `{path}` is not the exact static EIP-712 word path"
            ));
        }
    }

    u8::try_from(derived.len())
        .map_err(|_| format!("format `{sig}` has too many string-preimage fields"))
}

fn eip712_string_preimage_ordinal_for_field(
    enrollment: Option<&Eip712StringPreimageEnrollment>,
    field: &FieldDef,
) -> Option<u8> {
    let path = field.path.as_deref()?;
    enrollment?
        .fields
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.ordinal)
}

fn format_declares_sender_address(fmt: &Format) -> bool {
    fmt.fields.iter().any(|field| {
        field
            .params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .is_some_and(|params| params.contains_key("senderAddress"))
    })
}

fn format_declares_packed_v3_path(fmt: &Format) -> bool {
    fmt.fields
        .iter()
        .any(|field| field.format.as_deref() == Some("uniswapV3Path"))
}

/// Source-level belt for the singleton empty-`bytes` capability.
///
/// The exact enrollment key is necessary but not sufficient.  Independently
/// require one direct top-level `bytes` argument, one visible raw field that
/// consumes it, no formatter parameters, and the literal callback witness
/// label.  This prevents a future descriptor-hash update from reusing the tag
/// for nested topology or a different semantic meaning.
fn validate_exact_empty_bytes_format_source(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    enrollment: &ExactEmptyBytesEnrollment,
) -> Result<(), String> {
    if top_level_dynamic_arg_count(parsed)? != 1 {
        return Err(format!(
            "format `{sig}` exact-empty enrollment requires one sole dynamic top-level argument"
        ));
    }
    let matches: Vec<_> = fmt
        .fields
        .iter()
        .filter(|field| field.path.as_deref() == Some(enrollment.path))
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "format `{sig}` exact-empty path `{}` must be present exactly once, found {}",
            enrollment.path,
            matches.len()
        ));
    }
    let field = matches[0];
    if field.format.as_deref().unwrap_or("raw") != "raw"
        || field.visible.as_deref() != Some("always")
        || field.label.as_deref() != Some("Callback")
        || field
            .params
            .as_ref()
            .is_some_and(|params| !params.as_object().is_some_and(serde_json::Map::is_empty))
    {
        return Err(format!(
            "format `{sig}` exact-empty path `{}` must be the parameter-free, always-visible raw `Callback` field",
            enrollment.path
        ));
    }
    let member = enrollment
        .path
        .strip_prefix("#.")
        .ok_or_else(|| format!("format `{sig}` exact-empty path must be direct structured C1"))?;
    if member.is_empty()
        || member
            .bytes()
            .any(|byte| matches!(byte, b'.' | b'[' | b']'))
    {
        return Err(format!(
            "format `{sig}` exact-empty path `{}` is not a direct top-level field",
            enrollment.path
        ));
    }
    let Some(index) = parsed.top_names.iter().position(|name| name == member) else {
        return Err(format!(
            "format `{sig}` exact-empty path `{}` is not declared by the canonical signature",
            enrollment.path
        ));
    };
    if parsed.top_types.get(index).map(String::as_str) != Some("bytes")
        || semantic_terminal_type_for_path(enrollment.path, CTX_CONTRACT, parsed)? != "bytes"
    {
        return Err(format!(
            "format `{sig}` exact-empty path `{}` is not a top-level dynamic `bytes` terminal",
            enrollment.path
        ));
    }
    Ok(())
}

/// Re-derive every source fact represented by one nested-calldata enrollment.
/// The exact identity lookup is necessary but not sufficient: descriptor
/// source drift must fail before any authority-bearing TLV is emitted.
fn validate_nested_calldata_format_source(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    enrollment: &NestedCalldataEnrollment,
) -> Result<(), String> {
    if enrollment.execution != NestedCalldataExecution::CallZeroValue {
        return Err(format!(
            "format `{sig}` nested calldata has unsupported execution semantics"
        ));
    }
    let signature_hash = keccak256(parsed.types_signature.as_bytes());
    if enrollment.canonical_signature != parsed.types_signature
        || signature_hash[..4] != enrollment.parent_selector
    {
        return Err(format!(
            "format `{sig}` nested-calldata enrollment signature/selector drift"
        ));
    }
    if enrollment.evidence.repository.is_empty()
        || enrollment.evidence.revision.is_empty()
        || enrollment.evidence.deployment.is_empty()
        || enrollment.evidence.code_identity.is_empty()
    {
        return Err(format!(
            "format `{sig}` nested-calldata enrollment lacks exact source evidence identity"
        ));
    }

    let ordinal = enrollment.field_ordinal as usize;
    let field = fmt.fields.get(ordinal).ok_or_else(|| {
        format!("format `{sig}` nested-calldata enrollment field ordinal {ordinal} is absent")
    })?;
    if field.format.as_deref() != Some("calldata")
        || !matches!(field.visible.as_deref(), None | Some("always"))
    {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] must be always-visible calldata"
        ));
    }
    let field_path = field.path.as_deref().ok_or_else(|| {
        format!("format `{sig}` nested field[{ordinal}] is missing its bytes path")
    })?;
    if terminal_semantics_for_path(field_path, CTX_CONTRACT, parsed)?.kind
        != TerminalKind::DynamicBytes
    {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] does not terminate at dynamic bytes"
        ));
    }
    let compiled_field_path = compile_path(field_path, CTX_CONTRACT, parsed)?;
    let compiled_field_path: [u8; 5] = compiled_field_path.try_into().map_err(|_| {
        format!("format `{sig}` nested field[{ordinal}] is not the exact sole-C1 bytes path")
    })?;
    let field_slot = calldata_field_slot(&compiled_field_path).ok_or_else(|| {
        format!("format `{sig}` nested field[{ordinal}] is not the exact sole-C1 bytes path")
    })?;
    if compiled_field_path != enrollment.field_path {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] path differs from its exact enrollment"
        ));
    }
    let static_head_words = format_static_head_words(CTX_CONTRACT, parsed)?;
    if field_slot >= static_head_words {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] lies outside the static head"
        ));
    }

    let params = field
        .params
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            format!("format `{sig}` nested field[{ordinal}] requires calldata params")
        })?;
    if params.len() != 1 || !params.contains_key("calleePath") {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] permits only mandatory calleePath"
        ));
    }
    let callee_path = params["calleePath"].as_str().ok_or_else(|| {
        format!("format `{sig}` nested field[{ordinal}] calleePath must be a string")
    })?;
    let compiled_callee = compile_callee_address_path(callee_path, CTX_CONTRACT, parsed)?;
    if compiled_callee != enrollment.callee_path {
        return Err(format!(
            "format `{sig}` nested field[{ordinal}] calleePath differs from its exact enrollment"
        ));
    }
    match callee_location(&compiled_callee).ok_or_else(|| {
        format!("format `{sig}` nested field[{ordinal}] calleePath is not canonical")
    })? {
        NestedCalleeLocation::ContainerTo => {}
        NestedCalleeLocation::StaticWord(slot) if slot < static_head_words => {}
        NestedCalleeLocation::StaticWord(_) => {
            return Err(format!(
                "format `{sig}` nested field[{ordinal}] calleePath lies outside the static head"
            ))
        }
    }
    Ok(())
}

/// Source-level gate for the only dynamic-tuple shape the trusted IR admits.
/// The exact descriptor hash and deployment enrollment are necessary but not
/// sufficient: independently require the reviewed Router02 tuple/member names
/// and one visible full-path field so a future curation cannot reuse the
/// capability for a different `bytes` meaning.
fn validate_packed_v3_format_source(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), String> {
    let expected_members: &[&str] = match parsed.types_signature.as_str() {
        "exactInput((bytes,address,uint256,uint256))" => {
            &["path", "recipient", "amountIn", "amountOutMinimum"]
        }
        "exactOutput((bytes,address,uint256,uint256))" => {
            &["path", "recipient", "amountOut", "amountInMaximum"]
        }
        _ => {
            return Err(format!(
                "format `{sig}` is not an enrolled Router02 packed V3 signature"
            ))
        }
    };
    if parsed.top_names != ["params"]
        || parsed.top_types != ["(bytes,address,uint256,uint256)"]
        || parsed.inner_types.get("params").map(Vec::as_slice)
            != Some(&[
                "bytes".to_string(),
                "address".to_string(),
                "uint256".to_string(),
                "uint256".to_string(),
            ])
        || parsed
            .inner_names
            .get("params")
            .map(|names| names.iter().map(String::as_str).collect::<Vec<_>>())
            .as_deref()
            != Some(expected_members)
    {
        return Err(format!(
            "format `{sig}` does not have the exact enrolled `(bytes path,address recipient,uint256,uint256) params` shape"
        ));
    }

    let packed_fields = fmt
        .fields
        .iter()
        .filter(|field| field.format.as_deref() == Some("uniswapV3Path"))
        .collect::<Vec<_>>();
    if packed_fields.len() != 1 {
        return Err(format!(
            "format `{sig}` requires exactly one uniswapV3Path field, found {}",
            packed_fields.len()
        ));
    }
    let field = packed_fields[0];
    if field.path.as_deref() != Some("params.path")
        || field.visible.as_deref() != Some("always")
        || field
            .params
            .as_ref()
            .is_some_and(|params| !params.as_object().is_some_and(serde_json::Map::is_empty))
    {
        return Err(format!(
            "format `{sig}` packed path must be the visible, parameter-free full `params.path` field"
        ));
    }
    Ok(())
}

fn compile_sender_addresses(
    value: &serde_json::Value,
    ctx: &CompileCtx,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut push = |raw: &str, index: usize| -> Result<(), String> {
        let address = resolve_address_or_const(raw, ctx)?;
        if out
            .chunks_exact(20)
            .any(|existing| existing == address.as_slice())
        {
            return Err(format!(
                "addressName.senderAddress[{index}] duplicates an earlier address"
            ));
        }
        out.extend_from_slice(&address);
        Ok(())
    };

    match value {
        serde_json::Value::String(address) => push(address, 0)?,
        serde_json::Value::Array(addresses) => {
            if addresses.is_empty() {
                return Err("addressName.senderAddress list must not be empty".to_string());
            }
            if addresses.len() > MAX_SENDER_ADDRESSES {
                return Err(format!(
                    "addressName.senderAddress list has {} entries (max {MAX_SENDER_ADDRESSES})",
                    addresses.len()
                ));
            }
            for (index, value) in addresses.iter().enumerate() {
                let address = value.as_str().ok_or_else(|| {
                    format!("addressName.senderAddress[{index}] must be a string")
                })?;
                push(address, index)?;
            }
        }
        _ => {
            return Err(
                "addressName.senderAddress must be an address string or non-empty address array"
                    .to_string(),
            )
        }
    }
    Ok(out)
}

fn semantic_terminal_type_for_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<String, String> {
    match path.trim() {
        "@.to" | "@.from" => Ok("address".to_string()),
        "@.value" | "@.chainId" | "@.nonce" => Ok("uint256".to_string()),
        path if path.starts_with('@') => Err(format!(
            "semantic enrollment names unsupported container path `{path}`"
        )),
        path => rendered_path_terminal_type(path, context_kind, parsed)?
            .ok_or_else(|| format!("semantic enrollment path `{path}` has no terminal type")),
    }
}

fn validate_semantic_guard_word(
    guard: &SemanticWordGuard,
    semantics: TerminalSemantics,
) -> Result<(), String> {
    if !matches!(guard.operation, WORD_GUARD_EQ | WORD_GUARD_NE) {
        return Err(format!(
            "semantic guard `{}` has unknown operation 0x{:02x}",
            guard.path, guard.operation
        ));
    }
    match semantics.kind {
        TerminalKind::Address => {
            if guard.word[..12].iter().any(|&byte| byte != 0) {
                return Err(format!(
                    "semantic guard `{}` has a non-canonical address word",
                    guard.path
                ));
            }
        }
        TerminalKind::Unsigned => {
            let width = semantics.integer_width_bytes.ok_or_else(|| {
                format!("semantic guard `{}` unsigned type has no width", guard.path)
            })? as usize;
            if guard.word[..32 - width].iter().any(|&byte| byte != 0) {
                return Err(format!(
                    "semantic guard `{}` exceeds its authenticated unsigned width",
                    guard.path
                ));
            }
        }
        other => {
            return Err(format!(
                "semantic guard `{}` terminal {other:?} is not a static Address/Unsigned word",
                guard.path
            ))
        }
    }
    Ok(())
}

/// Validate and lower one exact source-level semantic enrollment.
///
/// Every enrolled path must exist exactly once in the descriptor's visible
/// flat field list and must retain the enrolled Solidity terminal type. This
/// deliberately refuses synthetic or hidden guard-only fields: the user sees
/// the same signed word whose predicate grants clear-signing authority.
fn apply_semantic_enrollment(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &CompileCtx,
    pool: &mut Pool,
    compiled: &mut [CompiledFieldOut],
    enrollment: &SemanticFormatEnrollment,
) -> Result<(), String> {
    if context_kind != CTX_CONTRACT || compiled.len() != fmt.fields.len() {
        return Err(format!(
            "format `{sig}` semantic enrollment requires one flat contract field per source field"
        ));
    }

    let sender_fields: Vec<usize> = fmt
        .fields
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            field
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .is_some_and(|params| params.contains_key("senderAddress"))
                .then_some(index)
        })
        .collect();
    if sender_fields.len() != 1 {
        return Err(format!(
            "format `{sig}` semantic enrollment requires exactly one senderAddress field, found {}",
            sender_fields.len()
        ));
    }
    let sender_index = sender_fields[0];
    let sender_field = &fmt.fields[sender_index];
    if sender_field.path.as_deref() != Some(enrollment.sender.path) {
        return Err(format!(
            "format `{sig}` senderAddress path {:?} does not match enrollment `{}`",
            sender_field.path, enrollment.sender.path
        ));
    }
    if parse_format_name(sender_field.format.as_deref().unwrap_or("raw"))? != FMT_ADDRESS_NAME {
        return Err(format!(
            "format `{sig}` senderAddress field must use addressName"
        ));
    }
    if !matches!(sender_field.visible.as_deref(), None | Some("always")) {
        return Err(format!(
            "format `{sig}` senderAddress field must be always visible"
        ));
    }
    let sender_type =
        semantic_terminal_type_for_path(enrollment.sender.path, context_kind, parsed)?;
    if sender_type != enrollment.sender.terminal_type || sender_type != "address" {
        return Err(format!(
            "format `{sig}` senderAddress terminal `{sender_type}` does not match enrolled `{}`",
            enrollment.sender.terminal_type
        ));
    }
    if enrollment.sender.sentinels.is_empty()
        || enrollment.sender.sentinels.len() > MAX_SENDER_ADDRESSES
    {
        return Err(format!(
            "format `{sig}` enrollment has invalid senderAddress cardinality {}",
            enrollment.sender.sentinels.len()
        ));
    }
    let source_sender = sender_field
        .params
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|params| params.get("senderAddress"))
        .ok_or_else(|| format!("format `{sig}` enrolled senderAddress is missing"))?;
    let sender_payload = compile_sender_addresses(source_sender, ctx)?;
    let expected_sender_payload: Vec<u8> = enrollment
        .sender
        .sentinels
        .iter()
        .flat_map(|address| address.iter().copied())
        .collect();
    if sender_payload != expected_sender_payload {
        return Err(format!(
            "format `{sig}` senderAddress values do not exactly match semantic enrollment"
        ));
    }
    compiled[sender_index].param_off = pool.append_param_tlv(
        compiled[sender_index].param_off,
        PARAM_SENDER_ADDRESS,
        &sender_payload,
    )?;

    apply_word_guards(
        sig,
        fmt,
        context_kind,
        parsed,
        pool,
        compiled,
        enrollment.guards,
    )
}

/// Validate and lower exact, always-visible scalar predicates shared by the
/// contract and EIP-712 enrollment paths.
fn validate_eip712_deployment_chain_guard(
    sig: &str,
    enrollment: &Eip712WordGuardEnrollment,
) -> Result<(), String> {
    let Some(path) = enrollment.deployment_chain_guard_path else {
        return Ok(());
    };
    let matching: Vec<_> = enrollment
        .guards
        .iter()
        .filter(|guard| guard.path == path)
        .collect();
    if matching.len() != 1 {
        return Err(format!(
            "format `{sig}` deployment-chain guard path `{path}` must have exactly one enrolled predicate, found {}",
            matching.len()
        ));
    }
    let guard = matching[0];
    let mut expected = [0u8; 32];
    expected[24..].copy_from_slice(&enrollment.chain_id.to_be_bytes());
    if guard.terminal_type != "uint256"
        || guard.operation != WORD_GUARD_EQ
        || guard.word != expected
    {
        return Err(format!(
            "format `{sig}` deployment-chain guard path `{path}` must equal the enrollment chain_id {} as uint256",
            enrollment.chain_id
        ));
    }
    Ok(())
}

fn apply_word_guards(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    pool: &mut Pool,
    compiled: &mut [CompiledFieldOut],
    guards: &[SemanticWordGuard],
) -> Result<(), String> {
    if compiled.len() != fmt.fields.len() {
        return Err(format!(
            "format `{sig}` word-guard enrollment requires one flat field per source field"
        ));
    }
    let mut guarded_paths = BTreeSet::new();
    for guard in guards {
        if !guarded_paths.insert(guard.path) {
            return Err(format!(
                "format `{sig}` semantic enrollment repeats guard path `{}`",
                guard.path
            ));
        }
        let matches: Vec<usize> = fmt
            .fields
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                (field.path.as_deref() == Some(guard.path)).then_some(index)
            })
            .collect();
        if matches.len() != 1 {
            return Err(format!(
                "format `{sig}` semantic guard path `{}` must be present exactly once, found {}",
                guard.path,
                matches.len()
            ));
        }
        let index = matches[0];
        let field = &fmt.fields[index];
        if !matches!(field.visible.as_deref(), None | Some("always")) {
            return Err(format!(
                "format `{sig}` semantic guard path `{}` must be always visible",
                guard.path
            ));
        }
        let terminal_type = semantic_terminal_type_for_path(guard.path, context_kind, parsed)?;
        if terminal_type != guard.terminal_type {
            return Err(format!(
                "format `{sig}` semantic guard path `{}` terminal `{terminal_type}` does not match enrolled `{}`",
                guard.path, guard.terminal_type
            ));
        }
        let (base, is_array) = split_array_suffix(&terminal_type);
        if is_array {
            return Err(format!(
                "format `{sig}` semantic guard path `{}` is not a static scalar",
                guard.path
            ));
        }
        let semantics = terminal_semantics_from_type(base)?;
        validate_semantic_guard_word(guard, semantics)?;

        let mut payload = [0u8; WORD_GUARD_PAYLOAD_LEN];
        payload[0] = guard.operation;
        payload[1..].copy_from_slice(&guard.word);
        compiled[index].param_off =
            pool.append_param_tlv(compiled[index].param_off, PARAM_WORD_GUARD, &payload)?;
    }
    Ok(())
}

/// Resolve a rendered path back to the canonical ABI/EIP-712 terminal type.
/// The path compiler already proves the navigation shape; this companion query
/// supplies type facts that the compact runtime IR otherwise lacks.
fn rendered_path_terminal_type(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<Option<String>, String> {
    let path = path.trim();
    let (structured, rest) = if let Some(r) = path.strip_prefix('#') {
        (true, r.trim_start_matches('.'))
    } else if path.starts_with('@') || path.starts_with('$') {
        (false, "")
    } else {
        (true, path)
    };
    if !structured {
        return Ok(None);
    }
    let segs = tokenize_path(rest)?;
    let mut names: Vec<&str> = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        match seg {
            PathSeg::Name(name) => names.push(name),
            // A whole-array wildcard followed by a member is the canonical
            // v2 array-of-struct path (`details.[].amount`). It changes the
            // traversal cardinality, not the element's semantic type, so keep
            // the array element type and continue into the named member.
            PathSeg::ArrayAll => {}
            PathSeg::ArrayIdx(_)
            | PathSeg::ArrayLast
            | PathSeg::ArraySlice(_, _)
            | PathSeg::ArraySliceLast(_)
                if i + 1 == segs.len() => {}
            _ => return Err(format!("path `{path}` has a non-terminal array operation")),
        }
    }
    let first = *names
        .first()
        .ok_or_else(|| format!("path `{path}` names no field"))?;
    let pos = parsed
        .top_names
        .iter()
        .position(|n| n == first)
        .ok_or_else(|| format!("path field `{first}` is not in the signature"))?;
    let mut ty = parsed.top_types[pos].clone();
    let mut parent_name = first;

    for &name in names.iter().skip(1) {
        if context_kind == CTX_CONTRACT {
            let member_names = parsed
                .inner_names
                .get(parent_name)
                .ok_or_else(|| format!("path descends into non-tuple `{parent_name}`"))?;
            let member_types = parsed
                .inner_types
                .get(parent_name)
                .ok_or_else(|| format!("path descends into non-tuple `{parent_name}`"))?;
            let member = member_names
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| format!("tuple `{parent_name}` has no member `{name}`"))?;
            ty = member_types[member].clone();
            parent_name = name;
        } else {
            let (base, _) = split_array_suffix(&ty);
            let members = parsed
                .struct_defs
                .get(base)
                .ok_or_else(|| format!("typed-data member `{base}` is not a struct"))?;
            let member = members
                .iter()
                .position(|(n, _)| n == name)
                .ok_or_else(|| format!("struct `{base}` has no member `{name}`"))?;
            ty = members[member].1.clone();
            parent_name = name;
        }
    }
    Ok(Some(ty))
}

/// Compact compiler-owned terminal semantics carried by schema v5.
///
/// `integer_width_bytes` is present iff `kind` is unsigned or signed. Keeping
/// the pair together prevents one lowering path (notably nested EIP-712 fields)
/// from emitting the broad kind while forgetting the authenticated width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalSemantics {
    kind: TerminalKind,
    integer_width_bytes: Option<u8>,
}

impl TerminalSemantics {
    const fn non_integer(kind: TerminalKind) -> Self {
        Self {
            kind,
            integer_width_bytes: None,
        }
    }

    const fn integer(kind: TerminalKind, width_bytes: u8) -> Self {
        Self {
            kind,
            integer_width_bytes: Some(width_bytes),
        }
    }
}

fn canonical_integer_width_bytes(base: &str, prefix: &str) -> Option<u8> {
    let width = base.strip_prefix(prefix)?;
    if width.len() > 1 && width.starts_with('0') {
        return None;
    }
    let bits = if width.is_empty() {
        256
    } else {
        width.parse::<u16>().ok()?
    };
    if !(8..=256).contains(&bits) || bits % 8 != 0 {
        return None;
    }
    u8::try_from(bits / 8).ok()
}

fn terminal_semantics_from_type(ty: &str) -> Result<TerminalSemantics, String> {
    let (base, _) = split_array_suffix(ty);
    if base == "address" {
        return Ok(TerminalSemantics::non_integer(TerminalKind::Address));
    }
    if base == "bool" {
        return Ok(TerminalSemantics::non_integer(TerminalKind::Bool));
    }
    if base == "string" {
        return Ok(TerminalSemantics::non_integer(TerminalKind::DynamicString));
    }
    if base == "bytes" {
        return Ok(TerminalSemantics::non_integer(TerminalKind::DynamicBytes));
    }
    if let Some(width_bytes) = canonical_integer_width_bytes(base, "uint") {
        return Ok(TerminalSemantics::integer(
            TerminalKind::Unsigned,
            width_bytes,
        ));
    }
    if let Some(width_bytes) = canonical_integer_width_bytes(base, "int") {
        return Ok(TerminalSemantics::integer(
            TerminalKind::Signed,
            width_bytes,
        ));
    }
    if let Some(width) = base.strip_prefix("bytes") {
        if matches!(width.parse::<u8>(), Ok(1..=32)) {
            return Ok(TerminalSemantics::non_integer(TerminalKind::FixedBytes));
        }
    }
    Err(format!(
        "terminal type `{ty}` has no schema-v5 device semantics"
    ))
}

fn terminal_semantics_for_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<TerminalSemantics, String> {
    let path = path.trim();
    if let Some(container) = path.strip_prefix('@') {
        return match container.trim_start_matches('.') {
            "to" | "from" => Ok(TerminalSemantics::non_integer(TerminalKind::Address)),
            "value" | "chainId" | "nonce" => {
                Ok(TerminalSemantics::integer(TerminalKind::Unsigned, 32))
            }
            other => Err(format!("unsupported container terminal `@.{other}`")),
        };
    }
    if path.starts_with('$') {
        return Err("metadata-rooted render fields have no signed terminal kind".to_string());
    }
    let ty = rendered_path_terminal_type(path, context_kind, parsed)?
        .ok_or_else(|| format!("path `{path}` has no typed terminal"))?;
    let (base, _) = split_array_suffix(&ty);
    if context_kind == CTX_EIP712 && type_is_struct(base, parsed) {
        return Ok(TerminalSemantics::non_integer(TerminalKind::NestedStruct));
    }
    terminal_semantics_from_type(&ty)
}

fn terminal_kind_for_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<TerminalKind, String> {
    Ok(terminal_semantics_for_path(path, context_kind, parsed)?.kind)
}

/// Emit the mandatory terminal-kind TLV and the schema-v5 integer-width TLV as
/// one invariant. The width is required exactly for signed/unsigned terminals.
fn push_terminal_semantics(out: &mut Vec<u8>, semantics: TerminalSemantics) -> Result<(), String> {
    push_tlv(out, PARAM_TERMINAL_KIND, &[semantics.kind as u8])?;
    match (semantics.kind, semantics.integer_width_bytes) {
        (TerminalKind::Unsigned | TerminalKind::Signed, Some(width @ 1..=32)) => {
            push_tlv(out, PARAM_INTEGER_WIDTH, &[width])
        }
        (TerminalKind::Unsigned | TerminalKind::Signed, _) => {
            Err("integer terminal has no canonical schema-v5 width".to_string())
        }
        (_, None) => Ok(()),
        (_, Some(_)) => Err("non-integer terminal carries schema-v5 integer width".to_string()),
    }
}

fn format_op_from_wire(format_op: u8) -> Result<FormatOp, String> {
    FormatOp::try_from(format_op).map_err(|_| format!("unknown format opcode 0x{format_op:02x}"))
}

fn param_mask_from_compiled_tlvs(body: &[u8]) -> Result<ParamMask, String> {
    let mut cursor = 0usize;
    let mut mask = ParamMask::NONE;
    while cursor < body.len() {
        let tag = *body
            .get(cursor)
            .ok_or_else(|| "truncated compiled parameter tag".to_string())?;
        let len = *body
            .get(cursor + 1)
            .ok_or_else(|| "truncated compiled parameter length".to_string())?
            as usize;
        cursor += 2;
        body.get(cursor..cursor + len)
            .ok_or_else(|| "truncated compiled parameter payload".to_string())?;
        cursor += len;
        let bit = match tag {
            PARAM_TOKEN_PATH => ParamMask::TOKEN_PATH,
            PARAM_TOKEN => ParamMask::TOKEN,
            PARAM_THRESHOLD => ParamMask::THRESHOLD,
            PARAM_MESSAGE => ParamMask::MESSAGE,
            PARAM_ADDR_TYPES => ParamMask::ADDR_TYPES,
            PARAM_ADDR_SOURCES => ParamMask::ADDR_SOURCES,
            PARAM_DATE_ENCODING => ParamMask::DATE_ENCODING,
            PARAM_ENUM_REF => ParamMask::ENUM_REF,
            PARAM_DECIMALS => ParamMask::DECIMALS,
            PARAM_BASE => ParamMask::BASE,
            PARAM_PREFIX => ParamMask::PREFIX,
            PARAM_SUFFIX => ParamMask::SUFFIX,
            PARAM_NESTED_SELECTOR => ParamMask::NESTED_SELECTOR,
            PARAM_NESTED_CALLEE => ParamMask::NESTED_CALLEE,
            PARAM_FALLBACK_LABEL => ParamMask::FALLBACK_LABEL,
            PARAM_CONST_VALUE => ParamMask::CONST_VALUE,
            PARAM_NESTED_STRUCT => ParamMask::NESTED_STRUCT,
            PARAM_NATIVE_CURRENCY => ParamMask::NATIVE_CURRENCY,
            PARAM_DYNAMIC_KIND => ParamMask::DYNAMIC_KIND,
            PARAM_NFT_COLLECTION => ParamMask::NFT_COLLECTION,
            PARAM_NFT_COLLECTION_PATH => ParamMask::NFT_COLLECTION_PATH,
            PARAM_EXACT_EMPTY_BYTES => ParamMask::EXACT_EMPTY_BYTES,
            PARAM_EIP712_STRING_PREIMAGE => ParamMask::EIP712_STRING_PREIMAGE,
            // Format metadata / mandatory terminal semantics are validated at
            // their own enclosing boundaries, not as formatter parameters.
            PARAM_VISIBILITY
            | PARAM_INTERPOLATED_INTENT
            | PARAM_TERMINAL_KIND
            | PARAM_INTEGER_WIDTH
            | PARAM_SENDER_ADDRESS
            | PARAM_WORD_GUARD => continue,
            other => return Err(format!("unknown compiled parameter tag 0x{other:02x}")),
        };
        mask = mask.union(bit);
    }
    Ok(mask)
}

fn is_signed_integer_type(ty: &str) -> bool {
    let (base, _) = split_array_suffix(ty);
    let Some(width) = base.strip_prefix("int") else {
        return false;
    };
    width.is_empty() || width.bytes().all(|b| b.is_ascii_digit())
}

fn format_interprets_numeric_sign(format_op: u8) -> bool {
    matches!(
        format_op,
        FMT_AMOUNT
            | FMT_TOKEN_AMOUNT
            | FMT_NFT_NAME
            | FMT_DATE
            | FMT_DURATION
            | FMT_ENUM
            | FMT_UNIT
            | FMT_CHAIN_ID
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn compile_one_field(
    sig: &str,
    field_idx: usize,
    field: &FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    emit_nested_marker: bool,
) -> Result<CompiledFieldOut, String> {
    compile_one_field_with_profile(
        sig,
        field_idx,
        field,
        context_kind,
        parsed,
        ctx,
        pool,
        enum_offsets,
        emit_nested_marker,
        false,
        false,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_one_field_with_profile(
    sig: &str,
    field_idx: usize,
    field: &FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    emit_nested_marker: bool,
    allow_packed_v3_path: bool,
    allow_exact_empty_bytes: bool,
    eip712_string_preimage_ordinal: Option<u8>,
    allow_nested_calldata: bool,
) -> Result<CompiledFieldOut, String> {
    if field.path.is_some() && field.value.is_some() {
        return Err(format!(
            "format `{sig}` field[{field_idx}] carries both `path` and constant `value`"
        ));
    }
    // 1. Compile the path bytecode — OR, for a path-less constant
    //    annotation field, capture its literal string.
    let (path_off, const_value): (u16, Option<String>) = match field.path.as_deref() {
        Some(path) => {
            let path_program =
                compile_path_with_profile(path, context_kind, parsed, allow_packed_v3_path)
                    .map_err(|e| format!("format `{sig}` field[{field_idx}] path `{path}`: {e}"))?;
            if path_program.len() > MAX_PATH_PROGRAM_LEN {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] path program too long ({} > {MAX_PATH_PROGRAM_LEN})",
                    path_program.len()
                ));
            }
            let mut path_blob = Vec::with_capacity(1 + path_program.len());
            path_blob.push(path_program.len() as u8);
            path_blob.extend_from_slice(&path_program);
            (pool.intern(&path_blob)?, None)
        }
        None => {
            // Constant-annotation field: a string `value`, no path. Renders
            // the literal attested string (e.g. the ERC-4626 vault note).
            let v = field.value.as_ref().ok_or_else(|| {
                format!("format `{sig}` field[{field_idx}] has neither `path` nor `value`")
            })?;
            let raw = v.as_str().ok_or_else(|| {
                format!("format `{sig}` field[{field_idx}] constant `value` must be a string")
            })?;
            let resolved = resolve_string_or_const(raw, ctx)
                .map_err(|e| format!("format `{sig}` field[{field_idx}] constant `value`: {e}"))?;
            let s = clean_ascii_exact(
                &resolved,
                MAX_POOL_TLV_PAYLOAD - 2,
                "constant annotation value",
            )?;
            if s.is_empty() || s.ends_with(' ') {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] constant `value` is empty or ends in ambiguous display padding"
                ));
            }
            if field
                .format
                .as_deref()
                .is_some_and(|format| format != "raw")
            {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] constant must use format `raw`"
                ));
            }
            if field
                .params
                .as_ref()
                .is_some_and(|p| !p.as_object().is_some_and(serde_json::Map::is_empty))
            {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] constant cannot carry formatter params"
                ));
            }
            (0u16, Some(s))
        }
    };

    // 2. Decide formatter opcode. A constant field renders its literal
    //    string regardless of the descriptor's `format`, so pin it to raw.
    let format_op = if const_value.is_some() {
        FMT_RAW
    } else {
        parse_format_name(field.format.as_deref().unwrap_or("raw"))?
    };

    let terminal_type = match field.path.as_deref() {
        Some(path) => rendered_path_terminal_type(path, context_kind, parsed)?,
        None => None,
    };
    let terminal_semantics = match (field.path.as_deref(), eip712_string_preimage_ordinal) {
        (Some(path), Some(_)) => {
            if context_kind != CTX_EIP712
                || rendered_path_terminal_type(path, context_kind, parsed)?.as_deref()
                    != Some("string")
            {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] string-preimage authority reached a non-EIP-712-string terminal"
                ));
            }
            TerminalSemantics::non_integer(TerminalKind::Eip712StringHashWord)
        }
        (Some(path), None) => terminal_semantics_for_path(path, context_kind, parsed)?,
        (None, None) if const_value.is_some() => {
            TerminalSemantics::non_integer(TerminalKind::ConstantText)
        }
        (None, _) => {
            return Err(format!(
                "format `{sig}` field[{field_idx}] has no schema-v5 terminal semantics"
            ))
        }
    };
    let terminal_kind = terminal_semantics.kind;
    // EIP-712 `encodeData` stores dynamic bytes/string as keccak256(value),
    // arrays as keccak256(concatenated encodings), and structs as hashStruct.
    // A flat field path therefore binds only the opaque 32-byte hash word, not
    // the value the descriptor claims to show. Successfully compiled nested
    // anchors bypass `compile_one_field` and decode their members against the
    // authenticated type shape; every other visible typed-data member must be
    // a scalar whose encodeData word is the value itself. The visibility gate
    // has already rejected every hidden non-address operand, including opaque
    // dynamic/hashStruct words.
    if context_kind == CTX_EIP712
        && eip712_string_preimage_ordinal.is_none()
        && field.visible.as_deref() != Some("never")
        && terminal_type
            .as_deref()
            .is_some_and(|ty| !eip712_member_is_static_scalar(ty))
    {
        return Err(format!(
            "format `{sig}` field[{field_idx}] visible EIP-712 terminal type `{}` is not a static scalar; encodeData carries an opaque hash word, not the display value",
            terminal_type.as_deref().unwrap_or("")
        ));
    }
    if terminal_type.as_deref().is_some_and(is_signed_integer_type)
        && format_interprets_numeric_sign(format_op)
    {
        return Err(format!(
            "format `{sig}` field[{field_idx}] uses signed integer type `{}` with a numeric formatter; device numeric formatters are unsigned-only",
            terminal_type.as_deref().unwrap_or("")
        ));
    }
    if context_kind == CTX_CONTRACT {
        match terminal_type.as_deref() {
            Some("string") if format_op != FMT_RAW => {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] dynamic `string` must use raw format; opcode 0x{format_op:02x} semantics cannot be ignored"
                ));
            }
            Some("bytes") if format_op == FMT_UNISWAP_V3_PATH && allow_packed_v3_path => {}
            Some("bytes") if format_op == FMT_RAW && allow_exact_empty_bytes => {}
            Some("bytes") if format_op == FMT_CALLDATA && allow_nested_calldata => {}
            Some("bytes") if format_op == FMT_CALLDATA => {
                return Err(format!(
                    "format `{sig}` nested calldata requires exactly one matching descriptor/deployment/signature/selector enrollment and one calldata field"
                ));
            }
            Some("bytes") => {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] has opaque dynamic `bytes`; the runtime intentionally has no injective renderer for arbitrary semantic bytes and would hard-refuse every payload, so this unusable format must not be advertised in the authenticated catalogue"
                ));
            }
            _ => {}
        }
    }
    if eip712_string_preimage_ordinal.is_some()
        && (format_op != FMT_RAW || !matches!(field.visible.as_deref(), None | Some("always")))
    {
        return Err(format!(
            "format `{sig}` field[{field_idx}] string-preimage authority requires a visible raw field"
        ));
    }

    // 3. Compile params + visibility into a single TLV blob.
    let mut param_blob = compile_params(
        sig,
        field_idx,
        format_op,
        field.params.as_ref(),
        field.visible.as_deref(),
        context_kind,
        parsed,
        ctx,
        enum_offsets,
        allow_packed_v3_path,
        allow_nested_calldata,
    )?;
    if let Some(cv) = &const_value {
        push_tlv(&mut param_blob, PARAM_CONST_VALUE, cv.as_bytes())?;
    }
    if context_kind == CTX_CONTRACT {
        match terminal_type.as_deref() {
            Some("string") => {
                push_tlv(&mut param_blob, PARAM_DYNAMIC_KIND, &[DYNAMIC_KIND_STRING])?
            }
            Some("bytes") if format_op == FMT_UNISWAP_V3_PATH && allow_packed_v3_path => {
                push_tlv(&mut param_blob, PARAM_DYNAMIC_KIND, &[DYNAMIC_KIND_BYTES])?
            }
            Some("bytes") if format_op == FMT_RAW && allow_exact_empty_bytes => {
                push_tlv(&mut param_blob, PARAM_DYNAMIC_KIND, &[DYNAMIC_KIND_BYTES])?;
                push_tlv(&mut param_blob, PARAM_EXACT_EMPTY_BYTES, &[])?;
            }
            Some("bytes") if format_op == FMT_CALLDATA && allow_nested_calldata => {
                push_tlv(&mut param_blob, PARAM_DYNAMIC_KIND, &[DYNAMIC_KIND_BYTES])?
            }
            _ => {}
        }
    }
    if let Some(ordinal) = eip712_string_preimage_ordinal {
        push_tlv(&mut param_blob, PARAM_EIP712_STRING_PREIMAGE, &[ordinal])?;
    }
    // Format-level nested-struct marker (see `has_nested_struct` in
    // `compile_one_format`). Parked on the first field; the device rejects
    // the whole format on encountering it. Payload is a single `0x01` so the
    // TLV is self-describing and a zero-length variant can be reserved later.
    if emit_nested_marker {
        push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &[0x01])?;
    }
    // Schema v5: authenticate the broad kind and, exactly for integer fields,
    // the Solidity width that the device needs for canonical padding checks.
    push_terminal_semantics(&mut param_blob, terminal_semantics)?;
    let policy_mask = param_mask_from_compiled_tlvs(&param_blob)?;
    let op = format_op_from_wire(format_op)?;
    let policy_mask = if emit_nested_marker && terminal_kind != TerminalKind::NestedStruct {
        // A bare v1 marker deliberately hard-refuses the whole format; validate
        // the underlying field semantics while treating the marker as an
        // enclosing refusal, not a formatter parameter.
        policy_mask.without(ParamMask::NESTED_STRUCT)
    } else {
        policy_mask
    };
    validate_field_policy(op, terminal_kind, policy_mask).map_err(|error| {
        format!(
            "format `{sig}` field[{field_idx}] formatter/type/parameter policy rejected \
             `{}` × {terminal_kind:?}: {error:?}",
            op.registry_name()
        )
    })?;
    let param_off = if param_blob.is_empty() {
        0u16
    } else {
        let mut blob_with_len = Vec::with_capacity(1 + param_blob.len());
        if param_blob.len() > MAX_POOL_TLV_PAYLOAD {
            return Err(format!(
                "format `{sig}` field[{field_idx}] param blob too long ({} > {MAX_POOL_TLV_PAYLOAD})",
                param_blob.len()
            ));
        }
        blob_with_len.push(param_blob.len() as u8);
        blob_with_len.extend_from_slice(&param_blob);
        pool.intern(&blob_with_len)?
    };

    // 4. Label.
    let label_raw = field.label.as_deref().unwrap_or("");
    let label = clean_ascii_truncated(label_raw, 254);
    if field.visible.as_deref() != Some("never") && !label_has_visible_glyph(label.as_bytes()) {
        return Err(format!(
            "format `{sig}` field[{field_idx}] has an empty post-sanitization visible label"
        ));
    }

    Ok(CompiledFieldOut {
        format_op,
        label: label.into_bytes(),
        path_off,
        param_off,
    })
}

/// Compile a format's fields as flat top-level records (the pre-Phase-5
/// behaviour). `emit_bare_marker` parks the bare `[0x01]` `PARAM_NESTED_STRUCT`
/// belt marker on the first field so the device declines the whole format —
/// used for an EIP-712 format whose nested-struct shape is not v1-supported.
#[allow(clippy::too_many_arguments)]
fn compile_flat_fields(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    emit_bare_marker: bool,
    allow_packed_v3_path: bool,
    exact_empty_bytes_path: Option<&str>,
    eip712_string_preimage_enrollment: Option<&Eip712StringPreimageEnrollment>,
    nested_calldata_enrollment: Option<&NestedCalldataEnrollment>,
) -> Result<Vec<CompiledFieldOut>, String> {
    let mut compiled: Vec<CompiledFieldOut> = Vec::with_capacity(fmt.fields.len());
    for (i, field) in fmt.fields.iter().enumerate() {
        let cf = compile_one_field_with_profile(
            sig,
            i,
            field,
            context_kind,
            parsed,
            ctx,
            pool,
            enum_offsets,
            emit_bare_marker && i == 0,
            allow_packed_v3_path,
            exact_empty_bytes_path.is_some_and(|path| field.path.as_deref() == Some(path)),
            eip712_string_preimage_ordinal_for_field(eip712_string_preimage_enrollment, field),
            nested_calldata_enrollment
                .is_some_and(|enrollment| enrollment.field_ordinal as usize == i),
        )?;
        compiled.push(cf);
    }
    Ok(compiled)
}

/// Emit the one canonical, schema-valid field used when nested lowering cannot
/// safely represent a descriptor. The bare `PARAM_NESTED_STRUCT=[0x01]` marker
/// is the only behaviorally relevant part: the device sees it before resolving
/// a field and rejects the whole format. A constant-text terminal and visible
/// label merely satisfy the ordinary schema-v5 field invariants without
/// depending on any unsupported descriptor path.
fn compile_bare_nested_refusal(pool: &mut Pool) -> Result<Vec<CompiledFieldOut>, String> {
    let mut param_blob = Vec::new();
    push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &[0x01])?;
    push_tlv(&mut param_blob, PARAM_CONST_VALUE, b"Unsupported")?;
    push_terminal_semantics(
        &mut param_blob,
        TerminalSemantics::non_integer(TerminalKind::ConstantText),
    )?;
    let param_off = intern_param_blob(pool, &param_blob)?;

    Ok(vec![CompiledFieldOut {
        format_op: FMT_RAW,
        label: b"Unsupported".to_vec(),
        path_off: 0,
        param_off,
    }])
}

/// One planned output record for an EIP-712 nested-struct format.
enum NestedPlan {
    /// A flat top-level field (its index into `fmt.fields`).
    Flat(usize),
    /// A nested-struct anchor: the struct top-member name, its word position in
    /// the parent `encodeData`, its struct base type, whether it is an ARRAY of
    /// that struct (v2), and the `fmt.fields` indices of its visible children (in
    /// descriptor order).
    Anchor {
        top: String,
        word_pos: u16,
        base: String,
        is_array: bool,
        children: Vec<usize>,
    },
}

/// Strip the nested-member prefix from a descriptor path, returning the single
/// elementary child segment. `top.child` (v1) → `child`; `top.[].child` (v2
/// array) → `child`. Returns `None` if the path doesn't match, has an unexpected
/// array bracket, or names more than one further segment (deeper nesting = v3).
/// Try to compile an EIP-712 format that has ≥1 nested-struct member into the
/// v0x03 recursive-IR shape (§4 + §10 + §11 of the design doc). Returns
/// `Some((records, nested_descent_count))` on a supported shape, or `Ok(None)`
/// to fall back to the bare-marker belt (the caller then emits flat fields +
/// `[0x01]` so the device declines the WHOLE format). `Err` only on a genuine
/// build error.
///
/// Supported subset — anything outside it returns `Ok(None)`:
///   * a single-level nested struct member (v1, `details.amount`) OR a
///     single-level ARRAY of a struct (v2, `details.[].amount`, `flags` bit0=1);
///     the `.[]` is stripped so local ordinals are identical either way;
///   * children are single-level (`a.b.c` / `a.[].b.c` → v3);
///   * the element/struct members are ELEMENTARY (a nested struct or deeper
///     array inside → v3);
///   * children use only the {raw, amount, tokenAmount(local tokenPath), date}
///     formats with the v1 param vocabulary;
///   * every address-typed local word is covered by a visible child (E2).
///
/// NOTE: v2 array anchors are EMITTED here (the wire is ready), but the on-device
/// ARRAY render is a separate, adversarial-review-gated commit — until then the
/// device declines any `is_array` anchor.
fn try_compile_eip712_nested(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    eip712_string_preimage_enrollment: Option<&Eip712StringPreimageEnrollment>,
) -> Result<Option<(Vec<CompiledFieldOut>, u8)>, String> {
    let mut plan: Vec<NestedPlan> = Vec::new();
    // top-member name -> index into `plan` of its anchor (first appearance).
    let mut anchor_at: BTreeMap<String, usize> = BTreeMap::new();

    for (i, field) in fmt.fields.iter().enumerate() {
        // Const-annotation / path-less fields are always flat top-level.
        let Some(path) = field.path.as_deref() else {
            plan.push(NestedPlan::Flat(i));
            continue;
        };
        let top = path.split('.').next().unwrap_or("").trim();
        let Some(pos) = parsed.top_names.iter().position(|n| n == top) else {
            // Unknown top member — let the flat path surface the real error, but
            // an array op on an unknown/non-struct member is not a shape we model.
            return Ok(None);
        };
        let (base, is_array) = split_array_suffix(&parsed.top_types[pos]);
        if !type_is_struct(base, parsed) {
            // Non-struct top member → flat field (unless it carries an array op
            // we don't model as a nested descent).
            if path.contains('[') {
                return Ok(None);
            }
            plan.push(NestedPlan::Flat(i));
            continue;
        }
        // The v0x03 array anchor models exactly one render-all array level.
        // Collapsing `T[][]` to the same boolean shape as `T[]` would let a
        // one-wildcard path authenticate an unrenderable two-level value.
        if array_suffix_dimensions(&parsed.top_types[pos]) > 1 {
            return Ok(None);
        }
        // Struct top member. v2 supports a single-level array of an
        // elementary-member struct; anything deeper → defer (belt-decline).
        if is_array && !array_element_is_v2_supported(base, parsed) {
            return Ok(None);
        }
        // The path must be strictly UNDER this struct member (a child). A bare
        // `top` (whole-struct render) or an indexed `[0]` defers; deep children
        // (`top.info.reactor` v3, `top.outputs.[].endAmount` v3, `top.child` v1,
        // `top.[].child` v2) are all handled by the recursive block compiler.
        let mut top_prefix = top.to_string();
        if is_array {
            top_prefix.push_str(".[]");
        }
        if strip_abs_prefix(path, &top_prefix).is_none() {
            return Ok(None);
        }
        let word_pos =
            u16::try_from(pos).map_err(|_| format!("format `{sig}`: too many top members"))?;
        if let Some(&ai) = anchor_at.get(top) {
            if let NestedPlan::Anchor { children, .. } = &mut plan[ai] {
                children.push(i);
            }
        } else {
            anchor_at.insert(top.to_string(), plan.len());
            plan.push(NestedPlan::Anchor {
                top: top.to_string(),
                word_pos,
                base: base.to_string(),
                is_array,
                children: std::vec![i],
            });
        }
    }

    // Second pass — compile each planned record.
    let mut compiled: Vec<CompiledFieldOut> = Vec::with_capacity(plan.len());
    let mut descent_count: u16 = 0;
    for item in &plan {
        match item {
            NestedPlan::Flat(i) => {
                let cf = compile_one_field_with_profile(
                    sig,
                    *i,
                    &fmt.fields[*i],
                    CTX_EIP712,
                    parsed,
                    ctx,
                    pool,
                    enum_offsets,
                    false,
                    false,
                    false,
                    eip712_string_preimage_ordinal_for_field(
                        eip712_string_preimage_enrollment,
                        &fmt.fields[*i],
                    ),
                    false,
                )?;
                compiled.push(cf);
            }
            NestedPlan::Anchor {
                top,
                word_pos,
                base,
                is_array,
                children,
            } => match compile_nested_anchor(
                sig, fmt, parsed, top, *word_pos, base, *is_array, children, pool,
            )? {
                Some((cf, descents)) => {
                    compiled.push(cf);
                    // RECURSIVE count (§12.5): this anchor + every nested
                    // sub-anchor it contains, so the E1 reconciliation pin matches
                    // the device's per-`render_nested_struct` `records_consumed`.
                    descent_count = descent_count
                        .checked_add(descents)
                        .ok_or_else(|| format!("format `{sig}`: too many nested descents"))?;
                }
                // A child we couldn't compile → belt-decline the WHOLE format.
                None => return Ok(None),
            },
        }
    }

    let descent_count = u8::try_from(descent_count)
        .map_err(|_| format!("format `{sig}`: too many nested descents"))?;
    Ok(Some((compiled, descent_count)))
}

/// Strip an absolute member prefix from a descriptor path, returning the path
/// RELATIVE to the struct/element that `prefix` names — or `None` if `path` is
/// not STRICTLY under `prefix` (a bare `prefix` = whole-struct reference → None).
/// `prefix` for an ARRAY element includes the trailing `.[]` (e.g.
/// `witness.outputs.[]`), so `witness.outputs.[].endAmount` → `endAmount`.
fn strip_abs_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.trim().strip_prefix(prefix)?.strip_prefix('.')?;
    if rest.is_empty() {
        return None;
    }
    Some(rest)
}

/// True iff an EIP-712 member type is a STATIC single-word scalar whose
/// `encodeData` word IS its value: `address` / `bool` / `uintN` / `intN` /
/// `bytesN` (`1 ≤ N ≤ 32`). A dynamic `bytes`/`string` (word = `keccak256(value)`,
/// not the value), an array (`T[]`), or a struct (word = `hashStruct`) is NOT a
/// static scalar. §12.6 hardening: an ELEMENTARY (non-struct) nested sub-field
/// must pass this or the compiler belt-declines — otherwise a *visible* dynamic
/// member would render its hash word as if it were the scalar value (shown≠signed).
fn eip712_member_is_static_scalar(mty: &str) -> bool {
    let t = mty.trim();
    if t.contains('[') {
        return false; // any array
    }
    if t == "address" || t == "bool" {
        return true;
    }
    if t == "bytes" || t == "string" {
        return false; // dynamic — encodeData word is keccak256(value)
    }
    if let Some(bits) = t.strip_prefix("uint").or_else(|| t.strip_prefix("int")) {
        return matches!(bits.parse::<u16>(), Ok(n) if (8..=256).contains(&n) && n % 8 == 0);
    }
    if let Some(n) = t.strip_prefix("bytes") {
        return matches!(n.parse::<u16>(), Ok(k) if (1..=32).contains(&k));
    }
    false
}

/// Compile one EIP-712 struct/array member into a `PARAM_NESTED_STRUCT` v0x03
/// PAYLOAD (version…sub_fields), returning `(payload, descent_count)` where
/// `descent_count` counts THIS anchor + every recursively-nested sub-anchor (the
/// E1 reconciliation pin, §12.5). RECURSIVE (v3): a child whose first path
/// segment names a struct member becomes a nested sub-anchor (recurse,
/// `is_array=false`); a segment naming an array-of-struct member becomes a nested
/// ARRAY sub-anchor (recurse, `is_array=true`, elements must be v2-supported
/// elementary structs). Elementary children stay v1-style LOCAL sub-fields.
/// `Ok(None)` (→ caller belt-declines the WHOLE format) on any unsupported shape:
/// depth `> MAX_STRUCT_DEPTH`, an uncompilable child, a *visible* dynamic member,
/// an uncovered address (E2), or a payload that overflows the pool TLV. Pins
/// `type_hash`/`member_count`/`addr_word_bmp` from `struct_defs` (never companion
/// data). `abs_prefix` is this element's absolute descriptor path (with `.[]` for
/// an array element); `children` are the `fmt.fields` indices under it.
#[allow(clippy::too_many_arguments)]
fn compile_nested_block(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    pool: &mut Pool,
    base: &str,
    is_array: bool,
    word_pos: u16,
    abs_prefix: &str,
    children: &[usize],
    depth: usize,
) -> Result<Option<(Vec<u8>, u16)>, String> {
    if depth > MAX_STRUCT_DEPTH {
        return Ok(None); // fail-closed: too deep to reason about / bound
    }
    let Some(members) = parsed.struct_defs.get(base) else {
        return Ok(None);
    };
    let member_count = members.len();
    if member_count == 0 || member_count > MAX_NESTED_MEMBERS {
        return Ok(None);
    }
    // type_hash = keccak(encodeType(nested)) — dbgen-PINNED (rule 3). An
    // encodeType build failure (malformed / undefined referenced struct) is NOT a
    // hard error: fall back to the bare-marker belt so the format still survives
    // compilation (declined), exactly as pre-Phase-5.
    let type_hash = match eip712_nested_type_hash(base, &parsed.struct_defs) {
        Ok(th) => th,
        Err(_) => return Ok(None),
    };

    // address-word bitmap (E2): bit i set iff local member i is bare `address`
    // (a struct/array member word is a hashStruct/array word, never an address).
    let bmp_len = member_count.div_ceil(8);
    let mut addr_bmp = std::vec![0u8; bmp_len];
    for (i, (_name, ty)) in members.iter().enumerate() {
        if eip712_member_word_is_address(ty) {
            addr_bmp[i / 8] |= 1u8 << (i % 8);
        }
    }

    // Group children by their first RELATIVE path segment (member name), in
    // FIRST-APPEARANCE order — this fixes the DFS descent/wire order (§12.4). An
    // elementary member → one v1-style sub-field; a struct/array-of-struct member
    // (with deeper children) → one nested sub-anchor (recurse).
    let mut group_order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &fi in children {
        let path = fmt.fields[fi].path.as_deref().unwrap_or("");
        let Some(rel) = strip_abs_prefix(path, abs_prefix) else {
            return Ok(None); // not strictly under this element (bare-struct ref, etc.)
        };
        let seg = rel.split(['.', '[']).next().unwrap_or("").trim();
        if seg.is_empty() {
            return Ok(None);
        }
        if !groups.contains_key(seg) {
            group_order.push(seg.to_string());
        }
        groups.entry(seg.to_string()).or_default().push(fi);
    }

    // `covered[w]` tracks the local words a SHOWN child binds (render path OR
    // tokenPath) for the E2 self-check.
    let mut covered = std::vec![false; member_count];
    let mut sub_fields: Vec<u8> = Vec::new();
    let mut sub_field_cnt: u8 = 0;
    let mut descent_count: u16 = 1; // this block itself

    for seg in &group_order {
        let seg_children = &groups[seg];
        let Some(local_ord) = members.iter().position(|(n, _)| n == seg) else {
            return Ok(None);
        };
        let local_ord_u16 = u16::try_from(local_ord).expect("member_count ≤ MAX_NESTED_MEMBERS");
        let (seg_base, seg_is_array) = split_array_suffix(&members[local_ord].1);

        if type_is_struct(seg_base, parsed) {
            // ── nested sub-anchor (struct member, or array-of-struct member) ──
            if array_suffix_dimensions(&members[local_ord].1) > 1 {
                return Ok(None);
            }
            // An array-of-struct element must be v2-renderable (elementary members)
            // to match the on-device per-element render; deeper shapes defer.
            if seg_is_array && !array_element_is_v2_supported(seg_base, parsed) {
                return Ok(None);
            }
            let mut child_prefix = std::format!("{abs_prefix}.{seg}");
            if seg_is_array {
                child_prefix.push_str(".[]");
            }
            let Some((child_payload, child_descents)) = compile_nested_block(
                sig,
                fmt,
                parsed,
                pool,
                seg_base,
                seg_is_array,
                local_ord_u16,
                &child_prefix,
                seg_children,
                depth + 1,
            )?
            else {
                return Ok(None);
            };
            // The recursive block accepted only after accounting for every one
            // of this member's leaves, so the parent hashStruct/array word is
            // covered as a complete child anchor rather than by a partial page.
            covered[local_ord] = true;
            if child_payload.len() > MAX_POOL_TLV_PAYLOAD - 2 {
                return Ok(None);
            }
            let mut param_blob: Vec<u8> = Vec::new();
            push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &child_payload)?;
            push_terminal_semantics(
                &mut param_blob,
                TerminalSemantics::non_integer(TerminalKind::NestedStruct),
            )?;
            validate_field_policy(
                FormatOp::Raw,
                TerminalKind::NestedStruct,
                param_mask_from_compiled_tlvs(&param_blob)?,
            )
            .map_err(|error| {
                format!("format `{sig}` nested anchor `{abs_prefix}.{seg}` policy: {error:?}")
            })?;
            let param_off = intern_param_blob(pool, &param_blob)?;
            // A nested-anchor sub-field renders nothing itself (its word is a
            // struct/array hashStruct word — never an address bit, so it needs no
            // E2 coverage); the device recurses on the marker, ignoring path_off.
            let label = clean_ascii_truncated(seg, 254);
            if !label_has_visible_glyph(label.as_bytes()) {
                return Err(format!(
                    "format `{sig}` nested anchor `{abs_prefix}.{seg}` has an empty post-sanitization label"
                ));
            }
            sub_fields.push(FMT_RAW);
            sub_fields.push(label.len() as u8);
            sub_fields.extend_from_slice(label.as_bytes());
            sub_fields.extend_from_slice(&0u16.to_be_bytes()); // path_off placeholder
            sub_fields.extend_from_slice(&param_off.to_be_bytes());
            sub_field_cnt = sub_field_cnt
                .checked_add(1)
                .ok_or_else(|| format!("format `{sig}`: too many nested sub-fields"))?;
            descent_count = descent_count
                .checked_add(child_descents)
                .ok_or_else(|| format!("format `{sig}`: too many nested descents"))?;
        } else {
            // ── elementary member → v1-style LOCAL sub-field ──
            // Exactly one field per elementary member; a deeper path into a
            // non-struct (`seg.more`) is malformed → decline.
            if seg_children.len() != 1 {
                return Ok(None);
            }
            let fi = seg_children[0];
            let field = &fmt.fields[fi];
            let path = field.path.as_deref().unwrap_or("");
            let rel = strip_abs_prefix(path, abs_prefix).unwrap_or("");
            if rel != *seg {
                return Ok(None); // `seg.more` where `seg` is not a struct
            }
            // §12.6 ABI-type gate: a member that CAN render must be a STATIC
            // single-word scalar (else a dynamic `bytes`/`string` would mis-render
            // its `keccak256(value)` word as the value). Rule 3 has already
            // rejected hidden non-address members, so `is_hidden` can only be an
            // exact address surfaced elsewhere; retaining this branch keeps the
            // nested compiler defensive if gate ordering changes.
            let is_hidden = field.visible.as_deref() == Some("never");
            if !is_hidden && !eip712_member_is_static_scalar(&members[local_ord].1) {
                return Ok(None);
            }
            let nested_format_op = parse_format_name(field.format.as_deref().unwrap_or("raw"))?;
            let terminal_semantics = terminal_semantics_from_type(&members[local_ord].1)?;
            let terminal_kind = terminal_semantics.kind;
            if is_signed_integer_type(&members[local_ord].1)
                && format_interprets_numeric_sign(nested_format_op)
            {
                return Err(format!(
                    "format `{sig}` nested field `{path}` uses signed integer type `{}` with a numeric formatter; device numeric formatters are unsigned-only",
                    members[local_ord].1
                ));
            }
            let Some((format_op, mut param_blob)) = compile_nested_subfield_params(
                field,
                abs_prefix,
                members,
                parsed,
                &mut covered,
                terminal_kind,
                !is_hidden,
            )?
            else {
                return Ok(None);
            };
            push_terminal_semantics(&mut param_blob, terminal_semantics)?;
            let op = format_op_from_wire(format_op)?;
            validate_field_policy(op, terminal_kind, param_mask_from_compiled_tlvs(&param_blob)?)
                .map_err(|error| {
                    format!(
                        "format `{sig}` nested field `{path}` formatter/type/parameter policy: {error:?}"
                    )
                })?;
            if !is_hidden && directly_displays_terminal(op, terminal_kind) {
                covered[local_ord] = true;
            }
            let render_prog = [
                PATHOP_ROOT_STRUCT,
                PATHOP_FIELD_IDX,
                (local_ord_u16 >> 8) as u8,
                (local_ord_u16 & 0xff) as u8,
            ];
            let path_off = intern_path_program(pool, &render_prog)?;
            let param_off = if param_blob.is_empty() {
                0u16
            } else {
                intern_param_blob(pool, &param_blob)?
            };
            let label = clean_ascii_truncated(field.label.as_deref().unwrap_or(""), 254);
            if !is_hidden && !label_has_visible_glyph(label.as_bytes()) {
                return Err(format!(
                    "format `{sig}` nested field `{path}` has an empty post-sanitization visible label"
                ));
            }
            sub_fields.push(format_op);
            sub_fields.push(label.len() as u8);
            sub_fields.extend_from_slice(label.as_bytes());
            sub_fields.extend_from_slice(&path_off.to_be_bytes());
            sub_fields.extend_from_slice(&param_off.to_be_bytes());
            sub_field_cnt = sub_field_cnt
                .checked_add(1)
                .ok_or_else(|| format!("format `{sig}`: too many nested sub-fields"))?;
        }
    }

    // Compiler self-check: every local member must be covered. Elementary
    // members are covered only by a successfully compiled visible child (or a
    // shown tokenAmount's local tokenPath); struct/array members are covered by
    // a recursively complete child anchor. The device independently re-checks
    // the address subset through `addr_bmp`; full signed-member completeness is
    // load-bearing here because the compact runtime IR intentionally carries no
    // general per-member type bitmap.
    for i in 0..member_count {
        if !covered[i] {
            return Ok(None);
        }
    }

    // Assemble the v0x03 PARAM_NESTED_STRUCT payload.
    let mut payload: Vec<u8> = Vec::new();
    payload.push(0x03); // version byte: structured block (vs bare `0x01` belt)
    payload.extend_from_slice(&word_pos.to_be_bytes());
    payload.extend_from_slice(&type_hash);
    payload.extend_from_slice(&(member_count as u16).to_be_bytes());
    payload.push(u8::from(is_array)); // flags: bit0 = is_array (v2); rest reserved 0
    payload.extend_from_slice(&addr_bmp);
    payload.push(sub_field_cnt);
    payload.extend_from_slice(&sub_fields);
    if payload.len() > MAX_POOL_TLV_PAYLOAD - 2 {
        return Ok(None); // overflow → belt-decline rather than truncate
    }
    Ok(Some((payload, descent_count)))
}

/// Compile one TOP-LEVEL nested-struct anchor into a `PARAM_NESTED_STRUCT` v0x03
/// record, returning `(record, descent_count)` where `descent_count` includes
/// every recursively-nested sub-anchor. Thin wrapper over [`compile_nested_block`]
/// (which owns the recursion) — builds the element's absolute prefix, wraps the
/// payload in the pool TLV, and emits the anchor field.
#[allow(clippy::too_many_arguments)]
fn compile_nested_anchor(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    top: &str,
    word_pos: u16,
    base: &str,
    is_array: bool,
    children: &[usize],
    pool: &mut Pool,
) -> Result<Option<(CompiledFieldOut, u16)>, String> {
    let mut abs_prefix = top.to_string();
    if is_array {
        abs_prefix.push_str(".[]");
    }
    let Some((payload, descent_count)) = compile_nested_block(
        sig,
        fmt,
        parsed,
        pool,
        base,
        is_array,
        word_pos,
        &abs_prefix,
        children,
        1,
    )?
    else {
        return Ok(None);
    };
    if payload.len() > MAX_POOL_TLV_PAYLOAD - 2 {
        return Ok(None);
    }
    let mut param_blob: Vec<u8> = Vec::new();
    push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &payload)?;
    push_terminal_semantics(
        &mut param_blob,
        TerminalSemantics::non_integer(TerminalKind::NestedStruct),
    )?;
    validate_field_policy(
        FormatOp::Raw,
        TerminalKind::NestedStruct,
        param_mask_from_compiled_tlvs(&param_blob)?,
    )
    .map_err(|error| format!("format `{sig}` nested anchor `{top}` policy: {error:?}"))?;
    let param_off = intern_param_blob(pool, &param_blob)?;
    // The anchor record renders nothing itself; the label carries the member name
    // for `erc7730.review.txt` readability.
    let label = clean_ascii_truncated(top, 254);
    if !label_has_visible_glyph(label.as_bytes()) {
        return Err(format!(
            "format `{sig}` nested anchor `{top}` has an empty post-sanitization label"
        ));
    }
    Ok(Some((
        CompiledFieldOut {
            format_op: FMT_RAW,
            label: label.into_bytes(),
            path_off: 0,
            param_off,
        },
        descent_count,
    )))
}

/// Parse a JSON `threshold` literal — a `0x…` hex string (≤ 64 nibbles) or a
/// non-negative JSON number — into a 32-byte BE u256, right-aligned. Returns
/// `None` for a `$`-const reference or a malformed value (the nested-subfield
/// path has no `ctx` for const resolution, so such a threshold defers to
/// belt-decline rather than being mis-parsed).
fn parse_literal_u256(v: &serde_json::Value) -> Option<[u8; 32]> {
    match v {
        serde_json::Value::String(s) => {
            let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            if h.is_empty() || h.len() > 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let padded = format!("{h:0>64}");
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(out)
        }
        serde_json::Value::Number(n) => {
            let x = n.as_u64()?;
            let mut out = [0u8; 32];
            out[24..32].copy_from_slice(&x.to_be_bytes());
            Some(out)
        }
        _ => None,
    }
}

/// Build a nested sub-field's format_op + LOCAL param TLV blob (visibility +
/// tokenAmount local `tokenPath` / `threshold` / `message` + date encoding).
/// Returns `Ok(None)` for any param shape we do not model (→ caller belt-declines
/// the format). Marks `covered[w]` for the local word a `tokenPath` IDs (E2 coverage).
fn compile_nested_subfield_params(
    field: &FieldDef,
    abs_prefix: &str,
    members: &[(String, String)],
    parsed: &ParsedFormatKey,
    covered: &mut [bool],
    terminal_kind: TerminalKind,
    shown: bool,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    let format_op = parse_format_name(field.format.as_deref().unwrap_or("raw"))?;
    let mut out: Vec<u8> = Vec::new();

    // Visibility — encode only if not the default `always`.
    if let Some(v) = field.visible.as_deref() {
        let byte = match v {
            "always" => VIS_ALWAYS,
            "never" => VIS_NEVER,
            "optional" => VIS_OPTIONAL,
            "if_not_in" | "ifNotIn" => VIS_IF_NOT_IN,
            "must_match" | "mustMatch" => VIS_MUST_MATCH,
            _ => return Ok(None),
        };
        if byte != VIS_ALWAYS {
            push_tlv(&mut out, PARAM_VISIBILITY, &[byte])?;
        }
    }

    let params = field.params.as_ref().and_then(|p| p.as_object());

    match format_op {
        FMT_RAW | FMT_AMOUNT => {
            // Elementary: no path-bearing params modelled in v1. If the
            // descriptor attaches params we don't understand, defer.
            if params.is_some_and(|o| !o.is_empty()) {
                return Ok(None);
            }
        }
        FMT_TOKEN_AMOUNT => {
            let Some(params) = params else {
                return Ok(None);
            };
            // A local `tokenPath` (required) plus the OPTIONAL `threshold` +
            // `message` "unlimited"-style display (the same top-level tokenAmount
            // vocabulary the device already renders). A fixed `token` or any other
            // key is not modelled in the nested path → defer to belt-decline.
            if params
                .keys()
                .any(|k| !matches!(k.as_str(), "tokenPath" | "threshold" | "message"))
            {
                return Ok(None);
            }
            let Some(tp) = params.get("tokenPath").and_then(|v| v.as_str()) else {
                return Ok(None);
            };
            // Strip THIS element's absolute prefix; the remaining single segment
            // is the local token member (a cross-struct / indexed / deep tokenPath
            // does not resolve here → defer). Authored ABSOLUTE (matches v2).
            let Some(tok_child) = strip_abs_prefix(tp, abs_prefix) else {
                return Ok(None);
            };
            if tok_child.contains('.') || tok_child.contains('[') {
                return Ok(None); // not a single local segment
            }
            let Some(tok_ord) = members.iter().position(|(n, _)| n == tok_child) else {
                return Ok(None);
            };
            let tok_ord = u16::try_from(tok_ord).expect("member_count ≤ MAX_NESTED_MEMBERS");
            if !token_path_displays_identity(format_op_from_wire(format_op)?, terminal_kind) {
                return Ok(None);
            }
            // A token identity must be the elementary scalar itself. Deriving a
            // broad terminal kind from `address[]` strips its suffix, and a
            // malicious EIP-712 tail may also define a custom struct literally
            // named `address`; either case would reinterpret an opaque array /
            // hashStruct word as a token address. Use the full parsed type path.
            if !token_path_surfaces_exact_scalar_address(tp, CTX_EIP712, parsed) {
                return Ok(None);
            }
            if shown {
                covered[tok_ord as usize] = true; // visibly bound token identity
            }
            let tok_prog = [
                PATHOP_ROOT_STRUCT,
                PATHOP_FIELD_IDX,
                (tok_ord >> 8) as u8,
                (tok_ord & 0xff) as u8,
            ];
            push_tlv(&mut out, PARAM_TOKEN_PATH, &tok_prog)?;
            // Optional threshold: a member `value >= threshold` renders `message`
            // (e.g. an all-ones limit → "Unlimited"). Parse a LITERAL hex/number
            // directly — the nested path has no `ctx` for const resolution, so a
            // `$`-const threshold defers (belt-decline).
            if let Some(th) = params.get("threshold") {
                let Some(raw) = parse_literal_u256(th) else {
                    return Ok(None);
                };
                push_tlv(&mut out, PARAM_THRESHOLD, &raw)?;
            }
            if let Some(msg) = params.get("message").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(msg, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_MESSAGE, s.as_bytes())?;
            }
        }
        FMT_DATE => {
            if let Some(params) = params {
                if params.keys().any(|k| k != "encoding") {
                    return Ok(None);
                }
                if let Some(enc) = params.get("encoding").and_then(|v| v.as_str()) {
                    let b = match enc {
                        "timestamp" => DATE_ENC_TIMESTAMP,
                        "blockheight" => DATE_ENC_BLOCKHEIGHT,
                        _ => return Ok(None),
                    };
                    push_tlv(&mut out, PARAM_DATE_ENCODING, &[b])?;
                }
            }
        }
        _ => return Ok(None), // any other nested format → v2+/unsupported
    }

    Ok(Some((format_op, out)))
}

/// Intern a path program into the pool (length-prefixed). Mirrors the inline
/// idiom in `compile_one_field`.
fn intern_path_program(pool: &mut Pool, prog: &[u8]) -> Result<u16, String> {
    if prog.len() > MAX_PATH_PROGRAM_LEN {
        return Err(format!(
            "nested path program too long ({} > {MAX_PATH_PROGRAM_LEN})",
            prog.len()
        ));
    }
    let mut blob = Vec::with_capacity(1 + prog.len());
    blob.push(prog.len() as u8);
    blob.extend_from_slice(prog);
    pool.intern(&blob)
}

/// Intern a param TLV blob into the pool (length-prefixed). Mirrors the inline
/// idiom in `compile_one_field`.
fn intern_param_blob(pool: &mut Pool, param_blob: &[u8]) -> Result<u16, String> {
    if param_blob.len() > MAX_POOL_TLV_PAYLOAD {
        return Err(format!(
            "nested param blob too long ({} > {MAX_POOL_TLV_PAYLOAD})",
            param_blob.len()
        ));
    }
    let mut blob = Vec::with_capacity(1 + param_blob.len());
    blob.push(param_blob.len() as u8);
    blob.extend_from_slice(param_blob);
    pool.intern(&blob)
}

fn compile_params(
    sig: &str,
    field_idx: usize,
    format_op: u8,
    params: Option<&serde_json::Value>,
    visible: Option<&str>,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    enum_offsets: &BTreeMap<String, u16>,
    allow_packed_v3_path: bool,
    allow_nested_calldata: bool,
) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();

    // Visibility — encode only if not the default `always`.
    if let Some(v) = visible {
        let byte = match v {
            "always" => VIS_ALWAYS,
            "never" => VIS_NEVER,
            "optional" => VIS_OPTIONAL,
            "if_not_in" | "ifNotIn" => VIS_IF_NOT_IN,
            "must_match" | "mustMatch" => VIS_MUST_MATCH,
            other => {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] unknown `visible`: {other:?}"
                ))
            }
        };
        if byte != VIS_ALWAYS {
            push_tlv(&mut out, PARAM_VISIBILITY, &[byte])?;
        }
    }

    let Some(params) = params else {
        if format_op == FMT_NFT_NAME {
            return Err(format!(
                "format `{sig}` field[{field_idx}] nftName requires exactly one of `collection` or `collectionPath`"
            ));
        }
        if format_op == FMT_CALLDATA {
            return Err(format!(
                "format `{sig}` field[{field_idx}] enrolled calldata requires a mandatory `calleePath` parameter"
            ));
        }
        return Ok(out);
    };
    let params = params
        .as_object()
        .ok_or_else(|| format!("format `{sig}` field[{field_idx}] `params` is not an object"))?;

    // Parameter keys are semantic. Silently ignoring a new/unsupported key can
    // make the trusted display implement a different formatter than the
    // descriptor requested, so accept only the subset the firmware implements.
    let allowed: &[&str] = match format_op {
        FMT_TOKEN_AMOUNT => &[
            "tokenPath",
            "token",
            "nativeCurrencyAddress",
            "threshold",
            "message",
        ],
        // `senderAddress` has authority beyond cosmetic address formatting: a
        // sentinel is substituted with the independently authenticated signer.
        // It is accepted syntactically only for addressName and is consumed
        // later by `apply_semantic_enrollment`, which requires an exact
        // descriptor/deployment/selector/path binding before emitting TLV 0x49.
        FMT_ADDRESS_NAME => &["types", "sources", "senderAddress"],
        FMT_INTEROP_ADDR_NAME => &["types", "sources"],
        FMT_NFT_NAME => &["collection", "collectionPath"],
        FMT_DATE => &["encoding"],
        FMT_ENUM => &["$ref", "ref"],
        FMT_UNIT => &["base", "decimals", "prefix"],
        FMT_CALLDATA => &["calleePath"],
        FMT_ENCRYPTED => &["fallbackLabel"],
        FMT_RAW | FMT_AMOUNT | FMT_DURATION | FMT_CHAIN_ID | FMT_TOKEN_TICKER
        | FMT_UNISWAP_V3_PATH => &[],
        _ => return Err(format!("unknown format opcode: 0x{format_op:02x}")),
    };
    for key in params.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "format `{sig}` field[{field_idx}] parameter `{key}` is unsupported for opcode 0x{format_op:02x}"
            ));
        }
    }

    // Per-formatter param dispatch.
    match format_op {
        FMT_TOKEN_AMOUNT => {
            if let Some(tp) = params.get("tokenPath") {
                let tp = tp
                    .as_str()
                    .ok_or_else(|| "tokenAmount.tokenPath must be a string".to_string())?;
                let prog =
                    compile_token_path_with_profile(tp, context_kind, parsed, allow_packed_v3_path)
                        .map_err(|e| format!("tokenPath `{tp}`: {e}"))?;
                push_tlv(&mut out, PARAM_TOKEN_PATH, &prog)?;
            }
            if let Some(t) = params.get("token") {
                let t = t
                    .as_str()
                    .ok_or_else(|| "tokenAmount.token must be a string".to_string())?;
                let bytes = resolve_address_or_const(t, ctx)?;
                push_tlv(&mut out, PARAM_TOKEN, &bytes)?;
            }
            // `nativeCurrencyAddress` accepts the ERC-7730 scalar or list
            // shape. Resolve constants now and authenticate the complete
            // descriptor-order list in IR; never truncate or silently drop a
            // member. The current local bound is registry-complete (two).
            if let Some(nca) = params.get("nativeCurrencyAddress") {
                let bytes = compile_native_currency_addresses(nca, ctx)?;
                push_tlv(&mut out, PARAM_NATIVE_CURRENCY, &bytes)?;
            }
            if let Some(th) = params.get("threshold") {
                let raw = match th {
                    serde_json::Value::String(s) => resolve_u256_or_const(s, ctx)?,
                    serde_json::Value::Number(n) => {
                        let mut b = [0u8; 32];
                        let v = n
                            .as_u64()
                            .ok_or_else(|| format!("threshold {n} not representable as u64"))?;
                        b[24..32].copy_from_slice(&v.to_be_bytes());
                        b
                    }
                    _ => return Err("threshold must be string or number".to_string()),
                };
                push_tlv(&mut out, PARAM_THRESHOLD, &raw)?;
            }
            if let Some(msg) = params.get("message") {
                let msg = msg
                    .as_str()
                    .ok_or_else(|| "tokenAmount.message must be a string".to_string())?;
                let s = clean_ascii_exact(msg, 16, "tokenAmount.message")?;
                push_tlv(&mut out, PARAM_MESSAGE, s.as_bytes())?;
            }
        }
        FMT_NFT_NAME => {
            let collection = params.get("collection");
            let collection_path = params.get("collectionPath");
            if collection.is_some() == collection_path.is_some() {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] nftName requires exactly one of `collection` or `collectionPath`"
                ));
            }
            if let Some(collection) = collection {
                let collection = collection
                    .as_str()
                    .ok_or_else(|| "nftName.collection must be a string".to_string())?;
                let address = resolve_address_or_const(collection, ctx)?;
                push_tlv(&mut out, PARAM_NFT_COLLECTION, &address)?;
            }
            if let Some(collection_path) = collection_path {
                let collection_path = collection_path
                    .as_str()
                    .ok_or_else(|| "nftName.collectionPath must be a string".to_string())?;
                let program = compile_path(collection_path, context_kind, parsed)
                    .map_err(|e| format!("collectionPath `{collection_path}`: {e}"))?;
                if program.as_slice() != NFT_COLLECTION_TO_PATH.as_slice() {
                    return Err(format!(
                        "nftName.collectionPath `{collection_path}` does not compile to the exact device-supported `@.to` collection path"
                    ));
                }
                push_tlv(&mut out, PARAM_NFT_COLLECTION_PATH, &program)?;
            }
        }
        FMT_ADDRESS_NAME | FMT_INTEROP_ADDR_NAME => {
            if let Some(types) = params.get("types") {
                let arr = types
                    .as_array()
                    .ok_or_else(|| "addressName.types must be an array".to_string())?;
                let mut bits = 0u8;
                for kind in arr {
                    let k = kind
                        .as_str()
                        .ok_or_else(|| "addressName `types` entry must be a string".to_string())?;
                    bits |= match k {
                        "wallet" => ADDR_TYPE_WALLET,
                        "eoa" => ADDR_TYPE_EOA,
                        "contract" => ADDR_TYPE_CONTRACT,
                        "nft_collection" | "nftCollection" => ADDR_TYPE_NFT_COLLECTION,
                        "token" => ADDR_TYPE_TOKEN,
                        "collection" => ADDR_TYPE_COLLECTION,
                        other => return Err(format!("addressName: unknown type `{other}`")),
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_TYPES, &[bits])?;
            }
            if let Some(sources) = params.get("sources") {
                let arr = sources
                    .as_array()
                    .ok_or_else(|| "addressName.sources must be an array".to_string())?;
                let mut bits = 0u8;
                for src in arr {
                    let s = src.as_str().ok_or_else(|| {
                        "addressName `sources` entry must be a string".to_string()
                    })?;
                    bits |= match s {
                        "local" => ADDR_SRC_LOCAL,
                        "ens" => ADDR_SRC_ENS,
                        "etherscan" => ADDR_SRC_ETHERSCAN,
                        "registry" => ADDR_SRC_REGISTRY,
                        other => return Err(format!("addressName: unknown source `{other}`")),
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_SOURCES, &[bits])?;
            }
            // `senderAddress`, when present, is deliberately not emitted here.
            // `compile_one_format` first proves an exact semantic enrollment,
            // then `apply_semantic_enrollment` resolves and emits it together
            // with every required word guard. Keeping the authority-bearing
            // lowering in one place prevents a generic params-only path from
            // silently unlocking another descriptor (notably the two Lido
            // formats that also publish this standard annotation).
        }
        FMT_DATE => {
            if let Some(enc) = params.get("encoding") {
                let enc = enc
                    .as_str()
                    .ok_or_else(|| "date.encoding must be a string".to_string())?;
                let b = match enc {
                    "timestamp" => DATE_ENC_TIMESTAMP,
                    "blockheight" => DATE_ENC_BLOCKHEIGHT,
                    other => return Err(format!("date.encoding: unknown `{other}`")),
                };
                push_tlv(&mut out, PARAM_DATE_ENCODING, &[b])?;
            }
        }
        FMT_DURATION => {
            // No params today; the renderer always reads the value as
            // seconds. Reserved for future use.
        }
        FMT_ENUM => {
            let refstr = params
                .get("$ref")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("ref").and_then(|v| v.as_str()))
                .ok_or_else(|| "enum format requires `$ref`".to_string())?;
            let name = refstr.strip_prefix("$.metadata.enums.").ok_or_else(|| {
                format!("enum $ref must start with $.metadata.enums.: `{refstr}`")
            })?;
            let off = enum_offsets
                .get(name)
                .copied()
                .ok_or_else(|| format!("enum `{name}` was not pre-interned"))?;
            push_tlv(&mut out, PARAM_ENUM_REF, &off.to_be_bytes())?;
        }
        FMT_UNIT => {
            if let Some(d) = params.get("decimals") {
                let d = d
                    .as_u64()
                    .ok_or_else(|| "unit.decimals must be a non-negative integer".to_string())?;
                if d > 255 {
                    return Err("unit.decimals > 255".to_string());
                }
                push_tlv(&mut out, PARAM_DECIMALS, &[d as u8])?;
            }
            let base = params
                .get("base")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "unit.base is required and must be a string".to_string())?;
            let resolved = resolve_string_or_const(base, ctx)?;
            let s = clean_ascii_exact(&resolved, MAX_POOL_TLV_PAYLOAD, "unit.base")?;
            if s.is_empty() || s.ends_with(' ') {
                return Err(
                    "unit.base must be non-empty and must not end in display padding".to_string(),
                );
            }
            push_tlv(&mut out, PARAM_BASE, s.as_bytes())?;
            if let Some(p) = params.get("prefix") {
                let p = p
                    .as_bool()
                    .ok_or_else(|| "unit.prefix must be a boolean".to_string())?;
                if p {
                    return Err(
                        "unit.prefix=true is unsupported by the trusted renderer".to_string()
                    );
                }
                push_tlv(&mut out, PARAM_PREFIX, &[u8::from(p)])?;
            }
        }
        FMT_CALLDATA => {
            if !allow_nested_calldata {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] calldata lacks an exact nested-calldata enrollment"
                ));
            }
            let callee = params
                .get("calleePath")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "format `{sig}` field[{field_idx}] enrolled calldata requires a string `calleePath`"
                    )
                })?;
            let program = compile_callee_address_path(callee, context_kind, parsed)
                .map_err(|error| format!("calleePath `{callee}`: {error}"))?;
            push_tlv(&mut out, PARAM_NESTED_CALLEE, &program)?;
        }
        FMT_ENCRYPTED => {
            let label = params
                .get("fallbackLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("[encrypted]");
            let s = clean_ascii_truncated(label, MAX_POOL_TLV_PAYLOAD);
            push_tlv(&mut out, PARAM_FALLBACK_LABEL, s.as_bytes())?;
        }
        FMT_RAW | FMT_AMOUNT | FMT_CHAIN_ID | FMT_TOKEN_TICKER | FMT_UNISWAP_V3_PATH => {
            // No formatter-specific params on the seed corpus today.
            // Any unrecognized keys are ignored — keeps us forward-
            // compatible with future spec extensions.
        }
        _ => return Err(format!("unknown format opcode: 0x{:02x}", format_op)),
    }

    Ok(out)
}

fn parse_format_name(name: &str) -> Result<u8, String> {
    Ok(match name {
        "raw" => FMT_RAW,
        "amount" => FMT_AMOUNT,
        "tokenAmount" => FMT_TOKEN_AMOUNT,
        "nftName" => FMT_NFT_NAME,
        "date" => FMT_DATE,
        "duration" => FMT_DURATION,
        "addressName" => FMT_ADDRESS_NAME,
        "enum" => FMT_ENUM,
        "unit" => FMT_UNIT,
        "calldata" => FMT_CALLDATA,
        "chainId" => FMT_CHAIN_ID,
        "tokenTicker" => FMT_TOKEN_TICKER,
        "interoperableAddressName" => FMT_INTEROP_ADDR_NAME,
        "uniswapV3Path" => FMT_UNISWAP_V3_PATH,
        // WYSIWYS (audit 2026-06-29): `encrypted` is REFUSED. There is no
        // honest way to clear-sign a value the format says to hide — the
        // firmware renderer would commit the field's path to the signed
        // digest while showing only a benign "[ENCRYPTED]" label, a
        // signed-but-not-shown operand on a page that looks like a normal
        // confirmation. A field that genuinely must not be displayed has to
        // be `visible:"never"` (excluded from the signed-and-shown set), not
        // rendered as `encrypted`. The firmware `render_encrypted` also
        // declines-to-blind as a runtime safety net.
        "encrypted" => {
            return Err("format `encrypted` is refused: it hides a signed operand \
                 (WYSIWYS). Use `visible:\"never\"` for fields that must not \
                 be displayed."
                .to_string())
        }
        other => return Err(format!("unknown format `{other}`")),
    })
}

// ─────────────────────────────────────────────────────────────────────
// Path compiler.
// ─────────────────────────────────────────────────────────────────────

/// Parsed view of a format key like
/// `"exactInputSingle((address tokenIn,address tokenOut,...) params)"`.
/// We strip parameter names for the keccak selector but keep them
/// indexed for path resolution.
#[derive(Debug)]
struct ParsedFormatKey {
    /// Types-only signature, e.g. `"exactInputSingle((address,address,...))"`.
    types_signature: String,
    /// The top-level argument names (root-level of `#.`).
    top_names: Vec<String>,
    /// The top-level argument *types*, positionally aligned with
    /// [`top_names`](Self::top_names). Needed to compute each field's ABI
    /// static head width so a calldata path resolves to the correct
    /// 32-byte head word and not a logical ordinal (see
    /// [`compile_structured_contract_path`] — closes the walker
    /// slot-confusion forgery class).
    top_types: Vec<String>,
    /// For tuple-typed top args, the inner names by top-arg name.
    /// e.g. `"params" -> ["tokenIn","tokenOut",...]`.
    /// For non-tuple top args this map is empty.
    inner_names: BTreeMap<String, Vec<String>>,
    /// Inner member *types* for tuple-typed top args, positionally aligned
    /// with [`inner_names`](Self::inner_names).
    inner_types: BTreeMap<String, Vec<String>>,
    /// EIP-712 referenced struct definitions parsed from the trailing
    /// `Struct(member…)Struct2(member…)` tail of an `encodeType` format key
    /// (`struct_name -> [(member_name, member_type)]`). Empty for contract
    /// format keys (which carry no such tail) and for EIP-712 primary types
    /// that reference no sub-structs. Needed to descend into nested typed-
    /// data members: a top-level member whose type is a struct name is a
    /// single opaque `hashStruct` word on the wire, so a fund-routing
    /// `address` nested inside it is committed to the signature yet invisible
    /// unless the visibility gate walks these definitions
    /// (`VULN-erc7730-eip712-nested-struct-address-hide`).
    struct_defs: BTreeMap<String, Vec<(String, String)>>,
}

/// Audit H-3 — contract-context field-completeness lint.
///
/// A clear-sign descriptor that silently omits an effect-bearing calldata
/// argument renders a benign-looking page while the signature still
/// commits to the hidden word (the canonical break: a
/// `transfer(address,uint256)` descriptor that declares only the amount
/// and never the recipient). The on-device renderer cannot reconstruct
/// ABI arity to catch the gap, so completeness is enforced HERE — where
/// every parameter of the function signature is known — and an
/// incomplete descriptor is refused at build time rather than pinned.
///
/// Every top-level parameter MUST be accounted for by at least one of:
///   * a field whose path resolves to it, at ANY visibility (the subsequent
///     visibility gate independently rejects signed-but-unseen operands);
///   * a `tokenAmount` field's `tokenPath`, which surfaces the parameter
///     as the token whose symbol labels the amount (e.g. Aave's `asset`).
///
/// Parameters reached only through `@`-container or `$`-metadata roots are
/// envelope / constant references, not calldata arguments, so they never
/// need their own coverage.
///
/// Granularity matches what the on-device renderer can address. The
/// renderer resolves a calldata path by SUMMING `FieldIdx` head-word slots
/// (`secure/src/tx/display/erc7730/formatters.rs::resolve_path`), so it
/// addresses each member of a *plain* static tuple individually. Coverage
/// is therefore enforced per static-tuple MEMBER, not merely per top-level
/// argument: a descriptor that walks `order.amount` but omits
/// `order.recipient` would render a benign page while the signature still
/// commits to the hidden recipient. Static arrays and array-of-tuple
/// arguments are NOT element-addressable on device (the renderer refuses
/// `ArrayIdx`), so they stay at top-level granularity. Nested tuples are
/// covered one level deep — the format-key parser captures a single inner
/// level, so a deeper member rides on its parent member's coverage.
fn check_contract_field_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), String> {
    if parsed.top_names.is_empty() {
        return Ok(()); // zero-argument function, e.g. `deposit()`.
    }

    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        // A *plain* static tuple — type `(...)` with no trailing `[]` array
        // suffix — has members the renderer addresses individually by ABI
        // head-word slot, so each member needs its own coverage.
        let top_ty = &parsed.top_types[idx];
        let plain_tuple_members = if top_ty.starts_with('(') && top_ty.ends_with(')') {
            parsed.inner_names.get(top_name).filter(|m| !m.is_empty())
        } else {
            None
        };

        match plain_tuple_members {
            Some(members) => {
                for member in members {
                    let covered = fmt.fields.iter().any(|field| {
                        field
                            .path
                            .as_deref()
                            .is_some_and(|p| path_covers_tuple_member(p, top_name, member))
                            || shown_token_path(field, CTX_CONTRACT, parsed).is_some_and(|tp| {
                                token_path_surfaces_exact_scalar_address(tp, CTX_CONTRACT, parsed)
                                    && path_covers_tuple_member(tp, top_name, member)
                            })
                    });
                    if !covered {
                        return Err(format!(
                            "format `{sig}`: tuple member `{top_name}.{member}` is neither \
                             rendered, explicitly hidden (`visible:\"never\"`), nor used as a \
                             `tokenPath`. The on-device renderer addresses static-tuple members \
                             individually, so every member must be accounted for or the trusted \
                             display can omit an effect-bearing field (audit H-3, tuple-member \
                             granularity)"
                        ));
                    }
                }
            }
            None => {
                let covered = fmt.fields.iter().any(|field| {
                    field
                        .path
                        .as_deref()
                        .is_some_and(|p| path_top_param_index(p, parsed) == Some(idx as u16))
                        || shown_token_path(field, CTX_CONTRACT, parsed).is_some_and(|tp| {
                            token_path_surfaces_exact_scalar_address(tp, CTX_CONTRACT, parsed)
                                && path_top_param_index(tp, parsed) == Some(idx as u16)
                        })
                });
                if !covered {
                    return Err(format!(
                        "format `{sig}`: parameter #{idx} (`{}`) is neither rendered, explicitly \
                         hidden (`visible:\"never\"`), nor fully surfaced by a scalar-address \
                         `tokenPath` — every \
                         contract-call argument must be accounted for so the trusted display \
                         cannot omit an effect-bearing field. An indexed/sliced tokenPath covers \
                         only one endpoint, not an entire signed array/bytes route (audit H-3)",
                        parsed.top_names[idx]
                    ));
                }
            }
        }
    }
    Ok(())
}

/// EIP-712 (typed-data) completeness lint — the typed-data sibling of
/// [`check_contract_field_completeness`] (audit 2026-06-25 HIGH-1).
///
/// The signed value is `structHash = keccak256(primary_type_hash ||
/// encoded_data)`, where every primary member contributes one word. This pass
/// accounts for those TOP-LEVEL words and preserves the established first-error
/// ordering for already-refused corpus entries. A second pass,
/// [`check_eip712_nested_field_completeness`], runs after visibility and proves
/// exact elementary-leaf coverage inside every expanded hashStruct. A child
/// path must never stand in for its siblings merely because they share one
/// opaque parent word.
///
/// Refuse to pin a descriptor unless every member is accounted for by a
/// field of its own (rendered or `visible:"never"`) or as another field's
/// `tokenPath`. Without this, an honest-but-incomplete descriptor (the
/// Permit/Permit2 approval shape is the canonical risk) would let the
/// firmware sign a member such as `spender` that never reaches a page —
/// exactly the signed-but-not-shown gap the contract lint already closes.
fn check_eip712_field_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), String> {
    if parsed.top_names.is_empty() {
        return Ok(()); // zero-member type (degenerate; nothing to sign).
    }

    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        let covered = fmt.fields.iter().any(|field| {
            field
                .path
                .as_deref()
                .is_some_and(|p| path_top_param_index(p, parsed) == Some(idx as u16))
                || shown_token_path(field, CTX_EIP712, parsed).is_some_and(|tp| {
                    token_path_surfaces_exact_scalar_address(tp, CTX_EIP712, parsed)
                        && path_top_param_index(tp, parsed) == Some(idx as u16)
                })
        });
        if !covered {
            return Err(format!(
                "EIP-712 format `{sig}`: member #{idx} (`{top_name}`) is neither rendered, \
                 explicitly hidden (`visible:\"never\"`), nor used as a `tokenPath`. Every \
                 typed-data member is folded into the signed structHash, so the trusted \
                 display must account for each one or it can omit an effect-bearing field \
                 such as an approval `spender` (audit 2026-06-25 HIGH-1, EIP-712 completeness)"
            ));
        }
    }
    Ok(())
}

/// Typed nested-completeness outcome. Unsupported structured-array rank is the
/// one admission failure that the caller converts into authenticated refusal
/// IR; every other failure remains a generator error.
#[derive(Debug)]
enum NestedCompletenessError {
    UnsupportedStructuredArrayRank(String),
    Refusal(String),
}

impl NestedCompletenessError {
    #[cfg(test)]
    fn contains(&self, needle: &str) -> bool {
        self.to_string().contains(needle)
    }
}

impl core::fmt::Display for NestedCompletenessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedStructuredArrayRank(message) | Self::Refusal(message) => {
                f.write_str(message)
            }
        }
    }
}

impl From<String> for NestedCompletenessError {
    fn from(message: String) -> Self {
        Self::Refusal(message)
    }
}

/// Require exact declaration coverage for every elementary member reachable
/// through an EIP-712 nested struct. The trusted nested renderer expands a
/// top-level hashStruct into member pages, so accounting for only the parent
/// word would allow `details.token` to hide the signed `details.amount`.
///
/// Struct arrays use the canonical render-all wildcard (`details.[].amount`),
/// and nested structs recurse to the same bounded depth as the compiler. A
/// direct field may be visible or explicitly hidden here (the preceding
/// visibility gate decides whether hiding it is safe); a tokenPath counts only
/// when a visible tokenAmount consumes that exact scalar-address leaf.
fn check_eip712_nested_field_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), NestedCompletenessError> {
    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        let top_ty = &parsed.top_types[idx];
        let (base, _) = split_array_suffix(top_ty);
        if !type_is_struct(base, parsed) {
            continue; // top-level scalar/array coverage is owned by the pass above.
        }
        // Rank is a property of the signed type, not of whichever descriptor
        // path happens to appear first. Check it before the bare-parent
        // first-error shortcut so `T[][]` cannot bypass this admission gate.
        if array_suffix_dimensions(top_ty) > 1 {
            return Err(NestedCompletenessError::UnsupportedStructuredArrayRank(format!(
                "EIP-712 format `{sig}`: nested member `{top_name}` has more than one array dimension (`{top_ty}`); trusted nested IR supports exactly one render-all array level"
            )));
        }
        // A field that targets the bare parent hashStruct is already refused by
        // the existing visible-hash terminal-type gate (or, if hidden, by the
        // visibility gate that ran immediately before this pass). Let that
        // established, more specific refusal fire instead of replacing it with
        // a missing-child diagnostic. A format with any bare-parent field can
        // never reach nested-anchor emission, even if it also lists children.
        if fmt.fields.iter().any(|field| {
            field
                .path
                .as_deref()
                .is_some_and(|path| path_matches_member(path, top_name))
        }) {
            continue;
        }
        let mut visited = Vec::new();
        check_eip712_nested_member_completeness(
            sig,
            fmt,
            parsed,
            top_name,
            top_ty,
            0,
            &mut visited,
        )?;
    }
    Ok(())
}

fn check_eip712_nested_member_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    member_path: &str,
    member_ty: &str,
    depth: usize,
    visited: &mut Vec<String>,
) -> Result<(), NestedCompletenessError> {
    let (base, is_array) = split_array_suffix(member_ty);
    if type_is_struct(base, parsed) {
        if array_suffix_dimensions(member_ty) > 1 {
            return Err(NestedCompletenessError::UnsupportedStructuredArrayRank(format!(
                "EIP-712 format `{sig}`: nested member `{member_path}` has more than one array dimension (`{member_ty}`); trusted nested IR supports exactly one render-all array level"
            )));
        }
        if depth > MAX_STRUCT_DEPTH || visited.iter().any(|seen| seen == base) {
            return Err(format!(
                "EIP-712 format `{sig}`: nested member `{member_path}` has a cyclic or deeper-than-{MAX_STRUCT_DEPTH} type; exact signed-leaf completeness cannot be proven"
            )
            .into());
        }
        let members = parsed
            .struct_defs
            .get(base)
            .ok_or_else(|| format!("EIP-712 struct `{base}` has no definition"))?;
        if members.is_empty() {
            return Err(format!(
                "EIP-712 format `{sig}`: nested member `{member_path}` has an empty struct type `{base}`; refusing an unrenderable hashStruct"
            )
            .into());
        }
        let element_path = if is_array {
            format!("{member_path}.[]")
        } else {
            member_path.to_string()
        };
        visited.push(base.to_string());
        for (child_name, child_ty) in members {
            let child_path = format!("{element_path}.{child_name}");
            check_eip712_nested_member_completeness(
                sig,
                fmt,
                parsed,
                &child_path,
                child_ty,
                depth + 1,
                visited,
            )?;
        }
        visited.pop();
        return Ok(());
    }

    let covered = fmt.fields.iter().any(|field| {
        field
            .path
            .as_deref()
            .is_some_and(|path| path_matches_member(path, member_path))
            || shown_token_path(field, CTX_EIP712, parsed).is_some_and(|token_path| {
                token_path_surfaces_exact_scalar_address(token_path, CTX_EIP712, parsed)
                    && path_matches_member(token_path, member_path)
            })
    });
    if covered {
        return Ok(());
    }

    Err(format!(
        "EIP-712 format `{sig}`: nested member `{member_path}` is neither rendered, explicitly hidden (`visible:\"never\"`), nor used as a shown tokenAmount's exact scalar-address `tokenPath`. Every elementary member folded into a nested hashStruct must be accounted for at exact leaf granularity"
    )
    .into())
}

/// Does descriptor `path` surface the calldata word for tuple member
/// `(tuple_name, member_name)`? True when the path's first segment is
/// `tuple_name` and its second segment — an explicit `.member` access — is
/// `member_name`. Paths rooted at `@`-container / `$`-metadata cover no
/// calldata member. A bare-tuple path (`tuple_name` with no member) or an
/// array-indexed first hop covers no specific member, matching the
/// renderer, which reads exactly one head word per resolved path.
fn path_covers_tuple_member(path: &str, tuple_name: &str, member_name: &str) -> bool {
    let path = path.trim();
    let rest = if let Some(r) = path.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if path.starts_with('@') || path.starts_with('$') {
        return false;
    } else {
        path
    };
    let end0 = rest.find(['.', '[']).unwrap_or(rest.len());
    if rest[..end0].trim() != tuple_name {
        return false;
    }
    // The member hop must be an explicit `.<member>` access (not `[i]`).
    let after = match rest[end0..].strip_prefix('.') {
        Some(a) => a,
        None => return false,
    };
    let end1 = after.find(['.', '[']).unwrap_or(after.len());
    after[..end1].trim() == member_name
}

/// Resolve the top-level function-argument index a descriptor `path`
/// touches, or `None` when the path roots at the `@`-container /
/// `$`-metadata namespace (no calldata argument) or names an argument the
/// format key does not declare.
fn path_top_param_index(path: &str, parsed: &ParsedFormatKey) -> Option<u16> {
    let path = path.trim();
    let rest = if let Some(r) = path.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if path.starts_with('@') || path.starts_with('$') {
        return None;
    } else {
        path
    };
    let end = rest.find(['.', '[']).unwrap_or(rest.len());
    let seg = rest[..end].trim();
    if seg.is_empty() {
        return None;
    }
    parsed
        .top_names
        .iter()
        .position(|nm| nm == seg)
        .map(|p| p as u16)
}

/// True when the ABI type string (parameter names already stripped by
/// [`parse_format_key`]) carries at least one `address` component:
/// `address`, `address[]`, `address[3]`, or a tuple / tuple-array containing
/// an address. ABI has no other type whose token is `address`, so a
/// token-exact scan is precise — `uint256` / `bytes32` / `bool` / `string`
/// never false-hit.
fn type_contains_address(ty: &str) -> bool {
    ty.split(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',') || c.is_whitespace())
        .any(|tok| tok == "address")
}

/// A field is *hidden* iff it is explicitly `visible:"never"`. Every other
/// visibility (`always` / absent / `optional` / `ifNotIn`) is potentially
/// shown, and `mustMatch` makes the on-device renderer reject the WHOLE
/// format (→ blind-sign), so none of them can leave an argument signed-but-
/// silently-hidden behind a clear-sign.
fn field_is_hidden(field: &FieldDef) -> bool {
    field.visible.as_deref() == Some("never")
}

/// A shown field path whose formatter actually consumes and displays its
/// authenticated terminal value.  Visibility/accounting gates must not give a
/// descriptor credit merely because a path is present: an inapplicable
/// formatter would otherwise turn a signed-but-unshown operand into apparent
/// coverage before the compiler's final policy check runs.
fn shown_direct_field_path<'a>(
    field: &'a FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Option<&'a str> {
    if field_is_hidden(field) {
        return None;
    }
    let path = field.path.as_deref()?;
    let op = parse_format_name(field.format.as_deref().unwrap_or("raw"))
        .ok()
        .and_then(|wire| format_op_from_wire(wire).ok())?;
    let terminal_kind = terminal_kind_for_path(path, context_kind, parsed).ok()?;
    directly_displays_terminal(op, terminal_kind).then_some(path)
}

/// The `tokenPath` of a shown `tokenAmount` field whose amount path has the
/// exact authenticated kind that makes the formatter consume the token
/// identity.  A stray `tokenPath` parameter on `raw`, a hidden field, or a
/// non-unsigned amount cannot receive completeness/visibility credit.
fn shown_token_path<'a>(
    field: &'a FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Option<&'a str> {
    if field_is_hidden(field) {
        return None;
    }
    let amount_path = field.path.as_deref()?;
    let op = parse_format_name(field.format.as_deref().unwrap_or("raw"))
        .ok()
        .and_then(|wire| format_op_from_wire(wire).ok())?;
    let terminal_kind = terminal_kind_for_path(amount_path, context_kind, parsed).ok()?;
    if !token_path_displays_identity(op, terminal_kind) {
        return None;
    }
    field
        .params
        .as_ref()
        .and_then(|p| p.get("tokenPath"))
        .and_then(|v| v.as_str())
}

/// True only when a `tokenPath` identifies the complete signed operand as one
/// elementary address. Endpoint extraction paths such as `path.[0]`,
/// `path.[-1]`, and `path.[0:20]` may label amount rows, but they do not expose
/// intermediate route elements/bytes and cannot satisfy whole-operand
/// completeness or visibility.
fn token_path_surfaces_exact_scalar_address(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> bool {
    rendered_path_terminal_type(path, context_kind, parsed).is_ok_and(|terminal| {
        terminal.as_deref() == Some("address")
            && !(context_kind == CTX_EIP712 && type_is_struct("address", parsed))
    })
}

/// A field path that surfaces the transaction's native value (`msg.value`)
/// via the `@`-envelope. Showing the native value is a meaningful,
/// effect-bearing thing to render (a payable `submit` / stake whose ETH IS
/// the intent), so a visible native-value field satisfies rule 1 even when
/// every calldata argument is a deliberately-hidden tag.
fn path_is_native_value(path: &str) -> bool {
    matches!(path.trim(), "@.value" | "@value")
}

/// An INERT top-level parameter role: it tells the user WHO signs or WHEN the
/// call is valid, never WHAT the call does. Showing only inert fields is the
/// hole `VULN-erc7730-rule1-inert-field-nonaddr-action-hide` drives through —
/// a `MetaTransaction(nonce, from, bytes functionSignature)` descriptor that
/// renders `from`+`nonce` (both inert) while hiding `functionSignature` (the
/// entire meta-executed action) paints a reassuring banner over a blind-sign.
///
/// Deliberately NARROW: self-identity (`from`/`sender`/`owner`/`holder`) and
/// replay/time roles (`nonce`/`salt`/`deadline`/`valid*`/`expiry`). It does
/// NOT include `signer`/`to`/`spender`/`recipient`/`target`/`account` — those
/// name the address a call ACTS ON (Celo `authorizeVoteSigner(address signer)`
/// shows exactly `signer`, a genuine effect), so treating them as inert would
/// wrongly refuse legitimate clear-signs. Case-insensitive; a single leading
/// `_` (common Solidity arg style) is stripped before matching.
///
/// This remains a RULE 1 refinement (require a shown EFFECT-BEARING field).
/// Rule 3 independently rejects every explicit hidden non-address operand;
/// both checks are useful so an inert-only descriptor fails for the clearest
/// reason even before individual hidden fields are classified.
fn is_inert_role_name(name: &str) -> bool {
    let n = name.trim().trim_start_matches('_').to_ascii_lowercase();
    matches!(
        n.as_str(),
        "from"
            | "sender"
            | "owner"
            | "holder"
            | "nonce"
            | "salt"
            | "deadline"
            | "validafter"
            | "validuntil"
            | "validbefore"
            | "expiry"
            | "expiration"
    )
}

/// WYSIWYS visibility gate — the sibling of the completeness lints
/// ([`check_contract_field_completeness`] /
/// [`check_eip712_field_completeness`]) that closes
/// `VULN-erc7730-visible-never-noparam-clearsign`.
///
/// Completeness proves every calldata / typed-data word is *declared* by
/// some field (rendered OR `visible:"never"`), so nothing is signed the
/// descriptor never mentions. It necessarily counts an explicit hide as
/// declared, but exactly the hole a hostile-or-careless (auto-vendored) descriptor
/// drives through: mark the recipient / target `visible:"never"` and the
/// device clear-signs a reassuring banner with the fund-routing argument
/// invisible.
///
/// This gate adds the missing invariant — a clear-signed known shape must
/// SHOW its effect-bearing arguments — via three fail-safe rules (a refused
/// format drops to loud blind-sign in the tolerant corpus, or hard-errors a
/// hand-authored strict descriptor so we fix it):
///
///  1. **No parameter-less clear-sign.** A function that takes ≥1 argument
///     must surface at least one of them (a visible field whose path
///     resolves to a calldata / typed argument). Refuses the all-
///     `visible:"never"` witness (`setAllowedTarget`, `transferOwnership`,
///     …) that renders banner + envelope + confirm and nothing else.
///  2. **No hidden fund-routing address.** Every `address`-typed argument
///     (top-level, and — for the contract path — each individually-
///     addressable static-tuple member) must be shown, either directly or
///     as the `tokenPath` of a shown amount. There is deliberately no
///     semantic allowlist: a signature/path-only exemption is not bound to
///     the authenticated deployment and could leak to a different contract
///     sharing the same ABI. This stops the *next* corpus resync from silently
///     shipping a recipient-hiding transfer/withdraw descriptor.
///  3. **No hidden non-address operand.** Every explicit `visible:"never"`
///     field is refused unless its terminal type is exactly `address` and
///     rule 2 proves that same signed address is surfaced elsewhere. Dynamic
///     payloads, arrays, tuples, packed routing words, nonces, deadlines, and
///     other scalars are all signed transaction semantics; classifying them
///     as harmless from type/name alone is unsound. A hostile descriptor can
///     name an arbitrary action `nonce` just as easily as `payload`.
///
/// The on-device renderer carries a coarse structural backstop for rule 1
/// (a contract format that declares fields but renders none falls through to
/// blind-sign), but rule 2 has no cheap on-device analogue — the device
/// can't reconstruct which hidden field was an `address` — so this build-
/// time gate is the load-bearing guarantee against partial hides.
fn check_field_visibility(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    context_kind: u8,
) -> Result<(), String> {
    // Rule 1 — the trusted screen must surface a genuinely EFFECT-BEARING
    // field, not merely SOME argument. A visible field satisfies rule 1 when
    // it resolves to a calldata argument that is NOT an inert self-identity /
    // replay role (a `tokenAmount`'s `path` resolves to the amount argument; a
    // routing/target address resolves to its param) OR to the native tx value
    // (a payable `submit`/stake whose ETH is the intent).
    //
    // Counting ANY shown argument (the pre-fix behaviour) let a descriptor
    // render only `from`+`nonce` — both inert — while hiding its sole
    // effect-bearing operand, painting a reassuring banner over a blind-sign
    // (`VULN-erc7730-rule1-inert-field-nonaddr-action-hide`; live witness the
    // Rarible `MetaTransaction` meta-tx forwarder). Requiring a non-inert
    // shown field refuses that shape while still passing Celo
    // `authorizeVoteSigner(address signer)` (the shown `signer` IS the effect).
    let any_shown_effect = fmt.fields.iter().any(|f| {
        shown_direct_field_path(f, context_kind, parsed).is_some_and(|p| {
            path_is_native_value(p)
                || path_top_param_index(p, parsed).is_some_and(|idx| {
                    parsed
                        .top_names
                        .get(idx as usize)
                        .is_some_and(|nm| !is_inert_role_name(nm))
                })
        })
    });
    if !parsed.top_names.is_empty() && !any_shown_effect {
        return Err(format!(
            "format `{sig}`: every shown field is an inert self-identity / replay role \
             (`from`/`owner`/`nonce`/`salt`/`deadline`/…) or the format is parameter-less, and \
             the native value is not shown — a clear-signed known shape must surface at least one \
             EFFECT-BEARING field (an amount, a routing/target address, or a state-changing \
             operand), else the trusted display shows only a reassuring banner while the user \
             blind-signs the call (WYSIWYS; VULN-erc7730-rule1-inert-field-nonaddr-action-hide / \
             VULN-erc7730-visible-never-noparam-clearsign). Drop the format or make an \
             effect-bearing field visible."
        ));
    }

    // Rule 2 — no hidden `address` argument.
    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        let top_ty = &parsed.top_types[idx];

        // Contract static-tuple members are addressed individually by the
        // renderer (mirrors the completeness lint) — descend one level.
        let members =
            if context_kind == CTX_CONTRACT && top_ty.starts_with('(') && top_ty.ends_with(')') {
                parsed
                    .inner_names
                    .get(top_name)
                    .zip(parsed.inner_types.get(top_name))
                    .filter(|(names, _)| !names.is_empty())
            } else {
                None
            };

        // EIP-712 typed-data member whose type is a nested struct: its
        // `address`es live behind an opaque `hashStruct` word, so descend
        // through the parsed struct definitions and require each nested
        // address to be shown — the fix for
        // `VULN-erc7730-eip712-nested-struct-address-hide`. Scalar EIP-712
        // members (and contract members) fall through to the checks below.
        if context_kind == CTX_EIP712 {
            let (base, is_array) = split_array_suffix(top_ty);
            if type_is_struct(base, parsed) {
                let mut visited: Vec<String> = Vec::new();
                check_eip712_member_addresses(
                    sig,
                    fmt,
                    parsed,
                    top_name,
                    top_ty,
                    is_array,
                    0,
                    &mut visited,
                )?;
                continue;
            }
        }

        match members {
            Some((member_names, member_types)) => {
                for (m_idx, member) in member_names.iter().enumerate() {
                    let m_ty = member_types.get(m_idx).map(String::as_str).unwrap_or("");
                    if !type_contains_address(m_ty) {
                        continue;
                    }
                    let shown = fmt.fields.iter().any(|f| {
                        shown_direct_field_path(f, context_kind, parsed)
                            .is_some_and(|p| path_covers_tuple_member(p, top_name, member))
                            || shown_token_path(f, context_kind, parsed).is_some_and(|tp| {
                                token_path_surfaces_exact_scalar_address(tp, context_kind, parsed)
                                    && path_covers_tuple_member(tp, top_name, member)
                            })
                    });
                    if !shown {
                        let arg_path = format!("{top_name}.{member}");
                        return Err(hidden_address_err(sig, &arg_path));
                    }
                }
            }
            None => {
                if !type_contains_address(top_ty) {
                    continue;
                }
                let shown = fmt.fields.iter().any(|f| {
                    shown_direct_field_path(f, context_kind, parsed)
                        .is_some_and(|p| path_top_param_index(p, parsed) == Some(idx as u16))
                        || shown_token_path(f, context_kind, parsed).is_some_and(|tp| {
                            token_path_surfaces_exact_scalar_address(tp, context_kind, parsed)
                                && path_top_param_index(tp, parsed) == Some(idx as u16)
                        })
                });
                if !shown {
                    return Err(hidden_address_err(sig, top_name));
                }
            }
        }
    }

    // Rule 3 — no explicit hidden operand. The ONLY structurally safe shape is
    // an exact scalar address that rule 2 has already proven is surfaced by a
    // different visible field (normally a tokenAmount `tokenPath`). Anything
    // else remains signed but unseen, including a dynamic EIP-712 hash word.
    for (field_idx, field) in fmt.fields.iter().enumerate() {
        if !field_is_hidden(field) {
            continue;
        }
        let Some(path) = field.path.as_deref() else {
            return Err(hidden_material_err(sig, field_idx, "<no path>", "<none>"));
        };
        let terminal_type = rendered_path_terminal_type(path, context_kind, parsed)
            .map_err(|_| hidden_material_err(sig, field_idx, path, "<unresolved>"))?
            .ok_or_else(|| hidden_material_err(sig, field_idx, path, "<container>"))?;
        // A hostile EIP-712 encodeType tail must not smuggle a custom struct
        // named `address` through the sole exception. `type_is_struct` makes
        // that ambiguity explicit even if a malformed descriptor reaches this
        // gate; only the elementary scalar is eligible.
        let exact_scalar_address = terminal_type == "address"
            && !(context_kind == CTX_EIP712 && type_is_struct("address", parsed));
        if !exact_scalar_address {
            return Err(hidden_material_err(sig, field_idx, path, &terminal_type));
        }
    }

    Ok(())
}

/// Recursively require every `address` reachable through an EIP-712 nested
/// struct `member` (at descriptor path `member_path`, ABI/struct type
/// `member_ty`) to be shown by a visible field. The fix for
/// `VULN-erc7730-eip712-nested-struct-address-hide`.
///
/// * A struct member (`member_ty` names a struct in the parsed tail) is
///   descended: each of its members is checked at path
///   `member_path.<inner>`. An *array*-of-struct member is not individually
///   addressable on device, so if it (transitively) reaches any address the
///   whole member is refused.
/// * A scalar `address` member must be covered by a visible field whose
///   `path` (or shown-amount `tokenPath`) resolves to exactly `member_path`.
///
/// Bounded by [`MAX_STRUCT_DEPTH`] and a `visited` set; a type too deep or
/// (malformed) cyclic is refused rather than reasoned about.
#[allow(clippy::too_many_arguments)]
fn check_eip712_member_addresses(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    member_path: &str,
    member_ty: &str,
    is_array: bool,
    depth: usize,
    visited: &mut Vec<String>,
) -> Result<(), String> {
    let (base, _) = split_array_suffix(member_ty);

    if type_is_struct(base, parsed) {
        if is_array {
            // Array-of-struct. v2 renders EVERY element (`M.[].child`), so an
            // address inside CAN be shown — for a v2-supported element (a struct
            // of ELEMENTARY members: no nested struct, no deeper array) descend
            // and apply the SAME per-element coverage check as the non-array
            // case, with `M.[].child` paths. An element that itself reaches a
            // nested struct or a deeper array is NOT v2-renderable → keep the
            // original refuse-if-reaches-address (fail-closed; v3 territory).
            if array_element_is_v2_supported(base, parsed) {
                let members = parsed.struct_defs.get(base).cloned().unwrap_or_default();
                for (m_name, m_ty) in &members {
                    let child_path = format!("{member_path}.[].{m_name}");
                    let (_, child_is_array) = split_array_suffix(m_ty);
                    check_eip712_member_addresses(
                        sig,
                        fmt,
                        parsed,
                        &child_path,
                        m_ty,
                        child_is_array,
                        depth + 1,
                        visited,
                    )?;
                }
                return Ok(());
            }
            let mut probe: Vec<String> = Vec::new();
            if struct_reaches_address(base, parsed, depth, &mut probe) {
                return Err(hidden_address_err(sig, member_path));
            }
            return Ok(());
        }
        if depth >= MAX_STRUCT_DEPTH || visited.iter().any(|v| v == base) {
            // Too deep / cyclic to reason about: fail closed on any address.
            let mut probe: Vec<String> = Vec::new();
            if struct_reaches_address(base, parsed, depth, &mut probe) {
                return Err(hidden_address_err(sig, member_path));
            }
            return Ok(());
        }
        visited.push(base.to_string());
        // Clone the member list so the recursive borrow of `parsed` is
        // immutable-only (host build; not perf-critical).
        let members = parsed.struct_defs.get(base).cloned().unwrap_or_default();
        for (m_name, m_ty) in &members {
            let child_path = format!("{member_path}.{m_name}");
            let (_, child_is_array) = split_array_suffix(m_ty);
            check_eip712_member_addresses(
                sig,
                fmt,
                parsed,
                &child_path,
                m_ty,
                child_is_array,
                depth + 1,
                visited,
            )?;
        }
        visited.pop();
        return Ok(());
    }

    // Scalar (non-struct) member: only `address`-bearing types matter.
    if !type_contains_address(base) {
        return Ok(());
    }
    let shown = fmt.fields.iter().any(|f| {
        shown_direct_field_path(f, CTX_EIP712, parsed)
            .is_some_and(|p| path_matches_member(p, member_path))
            || shown_token_path(f, CTX_EIP712, parsed)
                .is_some_and(|tp| path_matches_member(tp, member_path))
    });
    if !shown {
        return Err(hidden_address_err(sig, member_path));
    }
    Ok(())
}

/// Does descriptor `path` resolve to exactly the dotted typed-data member
/// `member_path` (e.g. `details.token`, `details.[].token`, `witness.info.reactor`)?
/// A leading `#`/`.` is normalised away; `@`-container / `$`-metadata roots cover
/// no message member. The whole-array WILDCARD segment `[]` IS matchable — v2
/// renders EVERY element of a `T[]`, so a per-element field/tokenPath
/// `M.[].child` covers `M.[].child` for every element. An INDEXED / sliced
/// segment (`[0]`, `[-1]`, `[0:20]`) names a specific element the gate cannot
/// reason about per-element and is rejected. Segments are compared literally, so
/// `[]` matches only `[]` (never a named member), keeping the address-coverage
/// decision exact.
fn path_matches_member(path: &str, member_path: &str) -> bool {
    let p = path.trim();
    let rest = if let Some(r) = p.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if p.starts_with('@') || p.starts_with('$') {
        return false;
    } else {
        p
    };
    // Reject INDEXED/sliced array segments (a specific element); allow the
    // whole-array wildcard `[]`.
    if rest
        .split('.')
        .any(|seg| seg.contains('[') && seg.trim() != "[]")
    {
        return false;
    }
    // Compare dot-separated segments, trimming incidental whitespace. `[]`
    // compares literally, so it matches only another `[]` wildcard segment.
    let mut a = rest.split('.').map(str::trim);
    let mut b = member_path.split('.').map(str::trim);
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn hidden_address_err(sig: &str, arg_path: &str) -> String {
    format!(
        "format `{sig}`: address argument `{arg_path}` is `visible:\"never\"` and never shown \
         (nor surfaced as a shown amount's `tokenPath`) — a hidden fund-routing address behind a \
         trusted clear-sign is a WYSIWYS break (VULN-erc7730-visible-never-noparam-clearsign). \
         Show it; semantic hidden-address exemptions are deliberately unsupported because they \
         cannot be inferred safely from an ABI signature/path."
    )
}

fn hidden_material_err(sig: &str, field_idx: usize, path: &str, terminal_type: &str) -> String {
    format!(
        "format `{sig}` field[{field_idx}] path `{path}` has terminal type `{terminal_type}` and \
         is `visible:\"never\"` — every signed non-address operand must be shown. Hidden bytes, \
         arrays, tuples, packed words, and scalars can change transaction semantics; dbgen cannot \
         classify them as harmless from their type or argument name. Only an exact `address` \
         already surfaced by another visible field/tokenPath may carry `visible:\"never\"`."
    )
}

/// The first name that appears more than once in `names` (empty names —
/// which no path can address — are ignored). A duplicate name defeats the
/// NAME-keyed tuple-member coverage/visibility gates
/// (`check_contract_field_completeness` + `check_field_visibility` rule 2 both
/// test membership with the position-blind `path_covers_tuple_member`): one
/// field would "cover" two distinct ABI slots, so an aliased effect-bearing
/// member (e.g. a duplicated `collateralToken` address that co-defines a
/// Morpho market) is signed but never rendered — a WYSIWYS break behind a
/// reassuring clear-sign. `parse_format_key` rejects it fail-closed. A real
/// Solidity function signature / struct never has duplicate parameter names,
/// so this refuses only malformed / crafted descriptors (→ loud blind-sign).
fn first_duplicate_name(names: &[String]) -> Option<&str> {
    for (i, n) in names.iter().enumerate() {
        if n.is_empty() {
            continue;
        }
        if names[..i].iter().any(|m| m == n) {
            return Some(n);
        }
    }
    None
}

fn parse_format_key(sig: &str) -> Result<ParsedFormatKey, String> {
    let sig = sig.trim();
    let name_end = sig
        .find('(')
        .ok_or_else(|| format!("missing '(' in format key `{sig}`"))?;
    let fname = &sig[..name_end];
    let rest = &sig[name_end..];

    let (args_str, types_args_str) = split_arg_list(rest)?;

    // Anything after the primary type's argument list is the EIP-712
    // `encodeType` tail: zero or more referenced struct definitions
    // (`Struct(member…)Struct2(member…)`). `split_arg_list` matched only the
    // FIRST paren group, so `rest[args_str.len()..]` is exactly this tail
    // (empty for a contract selector or a struct-free typed-data type). The
    // gate walks these to reach `address`es nested inside struct members.
    let struct_defs = parse_struct_defs(&rest[args_str.len()..])?;

    let types_signature = format!("{fname}{types_args_str}");

    // Now parse the top-level args of `args_str` (which includes the
    // surrounding parens).
    let inner = &args_str[1..args_str.len() - 1]; // strip outer ()
    let top_args = split_top_args(inner);

    let mut top_names = Vec::with_capacity(top_args.len());
    let mut top_types = Vec::with_capacity(top_args.len());
    let mut inner_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inner_types: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for arg in top_args {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if let Some(stripped) = arg.strip_prefix('(') {
            // Tuple-typed argument: `(inner_types... innerN names...) outer_name`.
            let close = find_matching_paren(arg.as_bytes(), 0)
                .ok_or_else(|| format!("unbalanced tuple in `{arg}`"))?;
            let tuple_body = &arg[1..close];
            let after = arg[close + 1..].trim();
            // Canonical tuple-array syntax places the array suffix before the
            // outer parameter name: `(address to,uint256 value)[] calls`.
            // Skip every suffix before applying renderer name policy.
            let array_suffix = collect_array_suffix(after);
            let outer_name = first_ident_or_empty(&after[array_suffix.len()..]);
            if outer_name.is_empty() {
                return Err(format!(
                    "top-level tuple arg has no name (need `(...types...) name`): `{arg}`"
                ));
            }
            top_names.push(outer_name.to_string());
            // Type string with all parameter names stripped (e.g.
            // `(address,address,uint24,...)` or `(...)[2]`).
            top_types.push(strip_one_arg(arg));
            // Parse inner field names + types.
            let inner_args = split_top_args(tuple_body);
            let mut names = Vec::with_capacity(inner_args.len());
            let mut types = Vec::with_capacity(inner_args.len());
            for inner_arg in inner_args {
                let inner_arg = inner_arg.trim();
                names.push(last_ident(inner_arg).to_string());
                types.push(strip_one_arg(inner_arg));
            }
            // WYSIWYS: the completeness + visibility gates resolve tuple members
            // by NAME (position-blind `path_covers_tuple_member`). A duplicate
            // member name would let ONE field cover TWO distinct ABI slots, so an
            // aliased effect-bearing member (e.g. a duplicated `collateralToken`
            // address that co-defines a Morpho market) is signed but never shown.
            // Reject fail-closed (a real Solidity struct has no dup member names).
            if let Some(dup) = first_duplicate_name(&names) {
                return Err(format!(
                    "tuple `{outer_name}` has duplicate member name `{dup}`; the on-device \
                     renderer and the completeness/visibility gates address tuple members by \
                     name, so a duplicate would hide the aliased member behind a trusted \
                     clear-sign (WYSIWYS). Refused."
                ));
            }
            inner_names.insert(outer_name.to_string(), names);
            inner_types.insert(outer_name.to_string(), types);
            let _ = stripped; // silence unused
        } else {
            top_names.push(last_ident(arg).to_string());
            top_types.push(strip_one_arg(arg));
        }
    }

    // Symmetric top-level guard. `path_top_param_index` IS position-aware, so a
    // duplicate top-level name is already caught downstream by completeness —
    // but reject it here too, fail-closed, so the rule is uniform with the
    // tuple-member guard above and a crafted descriptor never reaches the gates.
    if let Some(dup) = first_duplicate_name(&top_names) {
        return Err(format!(
            "format key has duplicate top-level argument name `{dup}`; a real function \
             signature has no duplicate parameter names. Refused."
        ));
    }

    Ok(ParsedFormatKey {
        types_signature,
        top_names,
        top_types,
        inner_names,
        inner_types,
        struct_defs,
    })
}

/// Parse the trailing struct-definition list of an EIP-712 `encodeType`
/// string — the part after the primary type's own argument list. The
/// canonical encoding appends every referenced struct, sorted, as
/// `Name(type name,type name,…)`; e.g. the tail of
/// `PermitSingle(PermitDetails details,…)PermitDetails(address token,…)`
/// is `PermitDetails(address token,…)`. Returns `name -> [(member_name,
/// member_type)]`. Names may be forward-referenced (a struct member whose
/// type is defined later in the tail), so callers must parse the whole tail
/// before resolving any member type.
///
/// Fails closed: a malformed tail (missing `(`, unbalanced parens, a
/// non-identifier name, or a duplicate definition) is an error, so a
/// hand-authored descriptor is rejected and a tolerant-corpus one drops to
/// blind-sign rather than silently under-parsing (which is what let the
/// nested-address hide slip the gate in the first place).
fn parse_struct_defs(tail: &str) -> Result<BTreeMap<String, Vec<(String, String)>>, String> {
    let mut defs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut rest = tail.trim();
    while !rest.is_empty() {
        let open = rest
            .find('(')
            .ok_or_else(|| format!("malformed EIP-712 struct-def tail (no `(`): `{rest}`"))?;
        let name = rest[..open].trim();
        if name.is_empty() || first_ident_or_empty(name) != name {
            return Err(format!("bad EIP-712 struct name in tail: `{name}`"));
        }
        let close = find_matching_paren(rest.as_bytes(), open)
            .ok_or_else(|| format!("unbalanced parens in EIP-712 struct def `{name}`"))?;
        let body = &rest[open + 1..close];
        let mut members: Vec<(String, String)> = Vec::new();
        for m in split_top_args(body) {
            let m = m.trim();
            if m.is_empty() {
                continue;
            }
            members.push((last_ident(m).to_string(), strip_one_arg(m)));
        }
        let member_names: Vec<String> = members
            .iter()
            .map(|(member_name, _)| member_name.clone())
            .collect();
        if let Some(dup) = first_duplicate_name(&member_names) {
            return Err(format!(
                "EIP-712 struct `{name}` has duplicate member name `{dup}`; referenced struct \
                 members are addressed by name, so the later member could be hidden behind the \
                 earlier member's trusted clear-sign. Refused."
            ));
        }
        if defs.insert(name.to_string(), members).is_some() {
            return Err(format!("duplicate EIP-712 struct def `{name}`"));
        }
        rest = rest[close + 1..].trim_start();
    }
    Ok(defs)
}

/// Split an ABI/typed-data type into its base type and whether it carries
/// any array suffix: `"DutchOutput[]"` → `("DutchOutput", true)`,
/// `"address"` → `("address", false)`, `"uint256[3][]"` → `("uint256",
/// true)`. Array elements are never individually addressable on device, so
/// the `is_array` flag gates the nested-address descent.
fn split_array_suffix(ty: &str) -> (&str, bool) {
    match ty.find('[') {
        Some(i) => (ty[..i].trim(), true),
        None => (ty.trim(), false),
    }
}

/// Number of array suffixes carried by a scalar/typed-data type. The existing
/// boolean splitter is sufficient for type classification, but nested IR must
/// distinguish `T[]` from `T[][]`: it authenticates exactly one array level.
fn array_suffix_dimensions(ty: &str) -> usize {
    ty.find('[')
        .map(|start| {
            ty.as_bytes()[start..]
                .iter()
                .filter(|&&b| b == b'[')
                .count()
        })
        .unwrap_or(0)
}

/// True when `base` (an array-stripped type name) is an EIP-712 struct
/// defined in the format key's tail.
fn type_is_struct(base: &str, parsed: &ParsedFormatKey) -> bool {
    parsed.struct_defs.contains_key(base)
}

/// A v2-renderable array element: a struct ALL of whose members are ELEMENTARY
/// (no member is itself a struct or an array). Deeper element shapes (a nested
/// struct or an array-in-element) are v3, so the address gate keeps its
/// fail-closed refuse for them. Kept in lockstep with the on-device array render
/// + emission, which only handle a single-level array of an elementary-member
/// struct.
fn array_element_is_v2_supported(base: &str, parsed: &ParsedFormatKey) -> bool {
    let Some(members) = parsed.struct_defs.get(base) else {
        return false;
    };
    members.iter().all(|(_n, ty)| {
        let (b, is_array) = split_array_suffix(ty);
        !is_array && !type_is_struct(b, parsed)
    })
}

/// True when the EIP-712 struct `base` transitively reaches an `address`
/// (directly, through a nested struct, or through an array-of-struct). Used
/// to decide whether an array-of-struct member — whose elements the device
/// cannot address individually — hides a fund-routing address. Bounded by
/// `MAX_STRUCT_DEPTH` and a visited set, so a (malformed) cyclic type is
/// treated as "contains an address" (fail-safe: refuse to clear-sign).
fn struct_reaches_address(
    base: &str,
    parsed: &ParsedFormatKey,
    depth: usize,
    visited: &mut Vec<String>,
) -> bool {
    if depth > MAX_STRUCT_DEPTH || visited.iter().any(|v| v == base) {
        return true; // fail safe — cannot prove address-free
    }
    let Some(members) = parsed.struct_defs.get(base) else {
        return false; // unknown non-struct base carries no address token here
    };
    visited.push(base.to_string());
    let reaches = members.iter().any(|(_, mty)| {
        let (mbase, _is_array) = split_array_suffix(mty);
        if type_is_struct(mbase, parsed) {
            struct_reaches_address(mbase, parsed, depth + 1, visited)
        } else {
            type_contains_address(mbase)
        }
    });
    visited.pop();
    reaches
}

// ─────────────────────────────────────────────────────────────────────
// Nested-EIP-712 (Phase 5) — per-struct metadata derivation.
//
// The device binds a nested-struct member by re-hashing
// `keccak(typeHash(nested) ‖ nested_ed)` and requiring equality with the
// committed parent word (see `docs/erc7730-nested-eip712-render-design.md`).
// `typeHash(nested)` must be dbgen-PINNED and canonical, so these functions
// rebuild the EIP-712 `encodeType` string from the parsed `struct_defs` and
// hash it. Pure host logic; unit-tested against foundry `cast keccak`.
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
type StructDefs = BTreeMap<String, Vec<(String, String)>>;

/// Reconstruct a single struct's canonical `encodeType` component:
/// `Name(type1 name1,type2 name2,…)` — the exact form the registry's format
/// key uses (space between type and name, comma between members, no other
/// whitespace), so `keccak` of the assembled string matches the on-chain
/// `typeHash`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_struct_def_string(name: &str, defs: &StructDefs) -> Result<String, String> {
    let members = defs
        .get(name)
        .ok_or_else(|| format!("EIP-712 struct `{name}` has no definition"))?;
    let mut s = String::with_capacity(name.len() + 2 + members.len() * 16);
    s.push_str(name);
    s.push('(');
    for (i, (mname, mty)) in members.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(mty);
        s.push(' ');
        s.push_str(mname);
    }
    s.push(')');
    Ok(s)
}

/// Transitively collect the struct types `name` references (array suffixes
/// stripped), EXCLUDING `name` itself. Bounded by `MAX_STRUCT_DEPTH`; a cyclic
/// / too-deep type errors (fail-closed — the format then drops to blind-sign).
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_collect_struct_deps(
    name: &str,
    defs: &StructDefs,
    out: &mut std::collections::BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_STRUCT_DEPTH {
        return Err(format!(
            "EIP-712 struct `{name}` nests deeper than {MAX_STRUCT_DEPTH}"
        ));
    }
    let Some(members) = defs.get(name) else {
        return Ok(());
    };
    for (_, mty) in members {
        let (base, _is_array) = split_array_suffix(mty);
        if defs.contains_key(base) && out.insert(base.to_string()) {
            eip712_collect_struct_deps(base, defs, out, depth + 1)?;
        }
    }
    Ok(())
}

/// Canonical EIP-712 `encodeType(name)` = `name`'s own def followed by the defs
/// of every transitively-referenced struct, sorted alphabetically (the EIP-712
/// rule). `BTreeSet` iterates in sorted order, so the concatenation is canonical.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_encode_type(name: &str, defs: &StructDefs) -> Result<String, String> {
    let mut deps: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    eip712_collect_struct_deps(name, defs, &mut deps, 0)?;
    deps.remove(name); // a self-referential type keeps only one copy of its own def
    let mut out = eip712_struct_def_string(name, defs)?;
    for dep in &deps {
        out.push_str(&eip712_struct_def_string(dep, defs)?);
    }
    Ok(out)
}

/// `typeHash(nested)` = `keccak256(encodeType(nested))` — dbgen-pinned, emitted
/// into the IR so the device can bind `keccak(typeHash ‖ nested_ed) == committed`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_nested_type_hash(name: &str, defs: &StructDefs) -> Result<[u8; 32], String> {
    Ok(keccak256(eip712_encode_type(name, defs)?.as_bytes()))
}

/// The NESTED struct's OWN member count — the number of 32-byte words in its
/// `encodeData`, which pins the exact `nested_ed` length (`member_count × 32`)
/// the device consumes and hashes (design rule 1 / E5).
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_member_count(name: &str, defs: &StructDefs) -> Result<usize, String> {
    defs.get(name)
        .map(Vec::len)
        .ok_or_else(|| format!("EIP-712 struct `{name}` has no definition"))
}

/// Whether a nested member's OWN 32-byte word is an `address` (so it must be
/// covered by a visible sub-field — the E2 standalone belt backstop). A member
/// whose type is itself a struct is a `hashStruct` word (its interior addresses
/// are covered by that struct's own descent + bitmap), not an address; an
/// array member is an offset/hash word (v2). So v1 marks only bare `address`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_member_word_is_address(mty: &str) -> bool {
    mty.trim() == "address"
}

/// `arg_list` starts with `(`. Returns the original substring plus a
/// types-only version (parameter names stripped).
fn split_arg_list(s: &str) -> Result<(String, String), String> {
    if !s.starts_with('(') {
        return Err(format!("expected '(' at start of `{s}`"));
    }
    let close = find_matching_paren(s.as_bytes(), 0)
        .ok_or_else(|| format!("unbalanced parens in `{s}`"))?;
    let args = &s[..=close];

    // Build types-only version by stripping the trailing identifier
    // from each comma-separated argument at every nesting depth.
    let types_only = strip_param_names(args);
    Ok((args.to_string(), types_only))
}

/// Strip parameter names from a type signature like `(address foo, uint256 bar)`
/// → `(address,uint256)`. Recurses into nested parentheses.
fn strip_param_names(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut depth = 0;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '(' => {
                if depth == 0 {
                    out.push('(');
                    start = i + 1;
                }
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = &s[start..i];
                    out.push_str(&strip_names_in_arg_list(inner));
                    out.push(')');
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    out
}

fn strip_names_in_arg_list(inner: &str) -> String {
    let parts = split_top_args(inner);
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&strip_one_arg(p.trim()));
    }
    out
}

fn strip_one_arg(arg: &str) -> String {
    if arg.starts_with('(') {
        // Nested tuple: keep parens, recurse into body, then drop the
        // trailing identifier (and any `[]` array suffix on it).
        let close = find_matching_paren(arg.as_bytes(), 0).unwrap();
        let inner = &arg[1..close];
        let after = arg[close + 1..].trim();
        // `after` may have an array suffix like `[]` before the name.
        let array_suffix = collect_array_suffix(after);
        let mut s = String::new();
        s.push('(');
        s.push_str(&strip_names_in_arg_list(inner));
        s.push(')');
        s.push_str(array_suffix);
        s
    } else {
        // Type can be `address`, `uint256`, `uint256[]`, `bytes32`, etc.
        // Drop any trailing identifier preceded by whitespace.
        let mut ty_end = arg.len();
        for (i, ch) in arg.char_indices() {
            if ch.is_whitespace() {
                ty_end = i;
                break;
            }
        }
        arg[..ty_end].to_string()
    }
}

fn collect_array_suffix(after_close: &str) -> &str {
    let trimmed = after_close.trim_start();
    // Look for `[...]` immediately following.
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        // Find matching ]
        let mut depth = 1;
        i += 1;
        while i < bytes.len() && depth > 0 {
            if bytes[i] == b'[' {
                depth += 1;
            } else if bytes[i] == b']' {
                depth -= 1;
            }
            i += 1;
        }
    }
    &trimmed[..i]
}

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn split_top_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(s[start..].to_string());
    }
    out
}

fn first_ident_or_empty(s: &str) -> &str {
    let s = s.trim_start();
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[..end]
}

fn last_ident(s: &str) -> &str {
    // Walk from the end, skipping `[]` suffixes, to find the trailing
    // identifier. If the entire string is a type (no name), return "".
    let s = s.trim();
    // Drop trailing array suffix(es).
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b']' {
        let mut depth = 1;
        end -= 1;
        while end > 0 && depth > 0 {
            end -= 1;
            if bytes[end] == b']' {
                depth += 1;
            } else if bytes[end] == b'[' {
                depth -= 1;
            }
        }
    }
    let cut = &s[..end].trim_end();
    let start = cut
        .rfind(|c: char| c.is_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    let candidate = &cut[start..];
    // If candidate is a known Solidity type prefix, treat as no-name.
    if candidate.is_empty() || candidate.starts_with(|c: char| c.is_ascii_digit()) {
        return "";
    }
    candidate
}

/// Compile a single ERC-7730 path string into the on-device opcode
/// sequence (without the leading length prefix; caller adds that).
/// ABI static head width of a type, in 32-byte words. `Dynamic` for
/// `bytes` / `string` / dynamic arrays / tuples containing a dynamic
/// member — their head slot holds only a 32-byte offset; the value lives
/// in the tail and is NOT readable from the static head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadWidth {
    Words(u32),
    Dynamic,
}

/// Words a type contributes to the ABI *head* (where the value — or, for
/// a dynamic type, its 32-byte tail offset — physically sits). A dynamic
/// predecessor still occupies exactly one head word, so summing this over
/// preceding siblings yields the correct head-word index of a later
/// static field.
fn head_slot_words(ty: &str) -> Result<u32, String> {
    Ok(match static_head_words(ty)? {
        HeadWidth::Words(n) => n,
        HeadWidth::Dynamic => 1,
    })
}

/// Count top-level ABI arguments whose head word is an offset into the dynamic
/// tail. Retained for the exact sole-empty-bytes enrollment, whose meaning is
/// intentionally narrower than generic authenticated multi-tail framing.
fn top_level_dynamic_arg_count(parsed: &ParsedFormatKey) -> Result<usize, String> {
    let mut count = 0usize;
    for ty in &parsed.top_types {
        if static_head_words(ty)? == HeadWidth::Dynamic {
            count = count
                .checked_add(1)
                .ok_or_else(|| "dynamic top-level argument count overflow".to_string())?;
        }
    }
    Ok(count)
}

/// Derive the authenticated, format-level topology for a bounded multi-tail
/// contract signature. Records cover every dynamic top-level argument in
/// canonical argument order, including arguments a descriptor marks hidden.
///
/// The legacy zero/one-tail encodings carry no marker. Multi-tail admission is
/// deliberately narrow: raw blobs (`bytes`/`string`) and dynamic arrays whose
/// elements are exactly one static ABI word. Tuple-local tails, dynamic array
/// elements, nested arrays, and fixed arrays containing dynamic values remain
/// outside this authority and fail closed at build time.
fn derive_dynamic_tail_topology(parsed: &ParsedFormatKey) -> Result<Option<Vec<u8>>, String> {
    let mut dynamic = Vec::new();
    let mut head_slot = 0u32;

    for ty in &parsed.top_types {
        let width = static_head_words(ty)?;
        if width == HeadWidth::Dynamic {
            dynamic.push((head_slot, ty.trim()));
        }
        let contribution = match width {
            HeadWidth::Words(words) => words,
            HeadWidth::Dynamic => 1,
        };
        head_slot = head_slot
            .checked_add(contribution)
            .ok_or_else(|| "top-level ABI head width overflow".to_string())?;
    }

    if dynamic.len() <= 1 {
        return Ok(None);
    }
    if dynamic.len() > MAX_DYNAMIC_TAILS {
        return Err(format!(
            "{} dynamic top-level arguments exceed the authenticated topology cap of {MAX_DYNAMIC_TAILS}",
            dynamic.len()
        ));
    }

    let count = u8::try_from(dynamic.len())
        .map_err(|_| "dynamic top-level argument count overflows u8".to_string())?;
    let mut payload = Vec::with_capacity(2 + dynamic.len() * 3);
    payload.push(TOPOLOGY_VERSION);
    payload.push(count);

    let mut previous_slot = None;
    for (slot, ty) in dynamic {
        let slot = u16::try_from(slot)
            .map_err(|_| format!("dynamic head slot {slot} for `{ty}` overflows u16"))?;
        if let Some(previous) = previous_slot {
            if slot <= previous {
                return Err(format!(
                    "dynamic head slots are not strictly increasing: {slot} follows {previous}"
                ));
            }
        }
        previous_slot = Some(slot);

        let kind = if matches!(ty, "bytes" | "string") {
            TAIL_KIND_BLOB
        } else if dynamic_array_static_elem(ty).is_some() {
            TAIL_KIND_STATIC_WORD_ARRAY
        } else {
            return Err(format!(
                "dynamic top-level type `{ty}` at head slot {slot} is unsupported by authenticated multi-tail topology; expected `bytes`, `string`, or `T[]` with one static primitive word"
            ));
        };
        payload.extend_from_slice(&slot.to_be_bytes());
        payload.push(kind);
    }

    Ok(Some(payload))
}

/// Recursively compute a type's ABI static head width. The crux of the
/// walker slot-confusion fix: a fixed array `T[N]` occupies `N ×
/// width(T)` head words and a static tuple the sum of its members, so a
/// calldata path that crosses one must advance by the true width, not by
/// one logical ordinal.
fn static_head_words(ty: &str) -> Result<HeadWidth, String> {
    let ty = ty.trim();
    if ty.is_empty() {
        return Err("empty ABI type".to_string());
    }
    // Trailing array suffix (innermost-last in Solidity) — peel from the
    // right so `T[2][3]` = 3 outer elements of `T[2]`.
    if let Some(open) = find_last_array_open(ty) {
        let base = &ty[..open];
        let suffix = &ty[open..];
        return match parse_fixed_array_len(suffix)? {
            None => Ok(HeadWidth::Dynamic), // `[]` — dynamic array.
            Some(count) => match static_head_words(base)? {
                // Fixed array of a dynamic type is itself dynamic.
                HeadWidth::Dynamic => Ok(HeadWidth::Dynamic),
                HeadWidth::Words(w) => Ok(HeadWidth::Words(w.saturating_mul(count))),
            },
        };
    }
    // Tuple.
    if ty.starts_with('(') {
        let close = find_matching_paren(ty.as_bytes(), 0)
            .ok_or_else(|| format!("unbalanced tuple type `{ty}`"))?;
        if close != ty.len() - 1 {
            return Err(format!("malformed tuple type `{ty}`"));
        }
        let mut total = 0u32;
        for member in split_top_args(&ty[1..close]) {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            match static_head_words(member)? {
                HeadWidth::Dynamic => return Ok(HeadWidth::Dynamic),
                HeadWidth::Words(w) => total = total.saturating_add(w),
            }
        }
        return Ok(HeadWidth::Words(total));
    }
    // Elementary type.
    if ty == "bytes" || ty == "string" {
        return Ok(HeadWidth::Dynamic);
    }
    match elementary_static_words(ty) {
        Some(w) => Ok(HeadWidth::Words(w)),
        None => Err(format!("unknown / unsupported ABI type `{ty}`")),
    }
}

/// Head words of an elementary (non-array, non-tuple) static type, or
/// `None` if `ty` is not a recognised single-word static type. `bytes` /
/// `string` are handled by the caller as dynamic.
fn elementary_static_words(ty: &str) -> Option<u32> {
    if ty == "address" || ty == "bool" || ty == "function" {
        return Some(1);
    }
    if let Some(rest) = ty.strip_prefix("uint").or_else(|| ty.strip_prefix("int")) {
        // `uint`/`int` (== 256) or `uintN`/`intN`, N a multiple of 8 ≤ 256.
        return if rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit()) {
            Some(1)
        } else {
            None
        };
    }
    if let Some(rest) = ty.strip_prefix("bytes") {
        // `bytes1..32` is static one-word; bare `bytes` was handled above.
        return if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            Some(1)
        } else {
            None
        };
    }
    None
}

/// Byte index of the `[` that opens the trailing array suffix of `ty`, or
/// `None` if `ty` does not end in an array suffix.
fn find_last_array_open(ty: &str) -> Option<usize> {
    let b = ty.as_bytes();
    if b.last() != Some(&b']') {
        return None;
    }
    let mut depth = 0i32;
    for i in (0..b.len()).rev() {
        match b[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse an array suffix `[N]` → `Some(N)`, `[]` → `None` (dynamic).
fn parse_fixed_array_len(suffix: &str) -> Result<Option<u32>, String> {
    let inner = suffix
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("bad array suffix `{suffix}`"))?
        .trim();
    if inner.is_empty() {
        return Ok(None);
    }
    inner
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("bad fixed-array length in `{suffix}`"))
}

/// Compile a rendered-VALUE path (the field's own `path`). Array index / byte
/// slice ops are REFUSED here — showing one element/slice of a value hides the
/// rest (the array-tail-hiding WYSIWYS hazard). This is the load-bearing half of
/// the tokenPath-only-slice invariant: only [`compile_token_path`] may emit an
/// extraction op, so a slice can never reach a shown value.
fn compile_path(path: &str, context_kind: u8, parsed: &ParsedFormatKey) -> Result<Vec<u8>, String> {
    compile_path_with_profile(path, context_kind, parsed, false)
}

/// Compile the first nested-calldata slice's callee authority.
///
/// Only exact `@.to` or one direct static `address` argument is accepted. A
/// generic one-word path is insufficient: uints, bytes32, `@.from`, nonce,
/// dynamic descent, tuples, arrays, and constants all refuse here.
fn compile_callee_address_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<[u8; 4], String> {
    if context_kind != CTX_CONTRACT {
        return Err("nested calldata calleePath is contract-context only".to_string());
    }
    let path = path.trim();
    if path != "@.to"
        && rendered_path_terminal_type(path, context_kind, parsed)?.as_deref() != Some("address")
    {
        return Err(format!(
            "calleePath `{path}` must terminate at one direct static address or exact `@.to`"
        ));
    }
    let program = compile_path(path, context_kind, parsed)?;
    let program: [u8; 4] = program.try_into().map_err(|_| {
        format!("calleePath `{path}` must compile to one canonical four-byte address path")
    })?;
    if callee_location(&program).is_none() {
        return Err(format!(
            "calleePath `{path}` is not exact `@.to` or a direct static address word"
        ));
    }
    Ok(program)
}

fn compile_path_with_profile(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    allow_packed_v3_path: bool,
) -> Result<Vec<u8>, String> {
    compile_path_inner(path, context_kind, parsed, false, allow_packed_v3_path)
}

/// Compile a `tokenPath` (a `tokenAmount`'s token-IDENTIFICATION address).
/// Unlike [`compile_path`] this MAY end in a single byte-slice / array-index
/// extraction op (`params.path.[0:20]`, `path.[-1]`) resolving the token address
/// packed inside a dynamic swap leg. The 20 bytes feed only an ERC-20 decimals/
/// symbol lookup — never a shown address — so a wrong extraction degrades an
/// amount to raw + `! raw, dec=?` (audit M-4), never a wrong recipient. See the
/// device resolver `render::resolve::resolve_token_address`.
fn compile_token_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<Vec<u8>, String> {
    compile_token_path_with_profile(path, context_kind, parsed, false)
}

fn compile_token_path_with_profile(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    allow_packed_v3_path: bool,
) -> Result<Vec<u8>, String> {
    let program = compile_path_inner(path, context_kind, parsed, true, allow_packed_v3_path)?;
    let exact_scalar = token_path_surfaces_exact_scalar_address(path, context_kind, parsed);
    let authenticated_target = program.as_slice() == NFT_COLLECTION_TO_PATH.as_slice();
    let checked_extraction = token_path_uses_checked_address_extraction(path, context_kind)?;
    if exact_scalar || authenticated_target || checked_extraction {
        return Ok(program);
    }
    Err(format!(
        "tokenPath `{path}` does not resolve to one authenticated token identity (an exact scalar address, `@.to`, or a checked 20-byte/address[] extraction)"
    ))
}

/// Whether `path` requests one of the contract-calldata extraction forms whose
/// type/width is proven by [`compile_token_path_extraction`]. This is evaluated
/// only after the path compiler succeeds; it distinguishes one selected token
/// address from the multi-value `[]` render-all program.
fn token_path_uses_checked_address_extraction(
    path: &str,
    context_kind: u8,
) -> Result<bool, String> {
    if context_kind != CTX_CONTRACT {
        return Ok(false);
    }
    let path = path.trim();
    let rest = if let Some(rest) = path.strip_prefix('#') {
        rest.trim_start_matches('.')
    } else if path.starts_with('@') || path.starts_with('$') {
        return Ok(false);
    } else {
        path
    };
    Ok(matches!(
        tokenize_path(rest)?.last(),
        Some(
            PathSeg::ArrayIdx(_)
                | PathSeg::ArrayLast
                | PathSeg::ArraySlice(_, _)
                | PathSeg::ArraySliceLast(_)
        )
    ))
}

fn compile_path_inner(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    is_token_path: bool,
    allow_packed_v3_path: bool,
) -> Result<Vec<u8>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("empty path".to_string());
    }

    // 1. Determine root.
    let (root, rest) = if let Some(r) = path.strip_prefix('#') {
        (PATHOP_ROOT_STRUCT, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('@') {
        (PATHOP_ROOT_CONTAINER, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('$') {
        (PATHOP_ROOT_METADATA, r.trim_start_matches('.'))
    } else {
        // Default root: structured (calldata for contract context;
        // typed-data message for EIP-712 — both addressed by name
        // through the same opcode).
        (PATHOP_ROOT_STRUCT, path)
    };

    let mut out = Vec::with_capacity(8);
    out.push(root);

    // Container names are a frozen envelope namespace, not ABI argument
    // names. Resolving `@.to` through `parsed.top_names` made it silently turn
    // into calldata ordinal 0 whenever a function also declared `address to`
    // (for example ERC-721 approve), while the device interprets the operand
    // as a keccak-prefix container discriminator. Compile this root from the
    // single-sourced constants so calldata names can never shadow it.
    if root == PATHOP_ROOT_CONTAINER {
        let segments = tokenize_path(rest)?;
        let name = match segments.as_slice() {
            [PathSeg::Name(name)] => *name,
            _ => {
                return Err(
                    "container path must name exactly one supported envelope field".to_string(),
                )
            }
        };
        let field = match name {
            "value" => pqsigner_erc7730::abi::container_field::VALUE,
            "to" => pqsigner_erc7730::abi::container_field::TO,
            "from" => pqsigner_erc7730::abi::container_field::FROM,
            "chainId" => pqsigner_erc7730::abi::container_field::CHAIN_ID,
            "nonce" => pqsigner_erc7730::abi::container_field::NONCE,
            _ => return Err(format!("unsupported container field `@.{name}`")),
        };
        out.push(PATHOP_FIELD_IDX);
        out.extend_from_slice(&field.to_be_bytes());
        return Ok(out);
    }

    // 2a. Contract-calldata structured paths emit *ABI head-word slots*
    //     (width-aware), not logical ordinals. This is the fix for the
    //     walker slot-confusion forgery: with logical ordinals a field
    //     preceded by a multi-word static type (fixed array / non-leading
    //     static tuple) resolved to the wrong calldata word, so the
    //     trusted display showed one value while the contract executed on
    //     another. See `compile_structured_contract_path` +
    //     `docs/security/vulns/VULN-erc7730-walker-slot-confusion.md`.
    if root == PATHOP_ROOT_STRUCT && context_kind == CTX_CONTRACT {
        compile_structured_contract_path(
            &tokenize_path(rest)?,
            parsed,
            &mut out,
            is_token_path,
            allow_packed_v3_path,
        )?;
        return Ok(out);
    }

    // 2b. Container (`@`) / metadata (`$`) roots, and EIP-712 message
    //     roots, keep the existing encoding: container/metadata field
    //     names resolve to keccak-prefix discriminators the on-device
    //     envelope resolver matches, and EIP-712 `encodeData` lays out
    //     every member as exactly one 32-byte word so the logical ordinal
    //     IS the word slot. Do NOT apply ABI widths here.
    let mut cur_top: Option<&str> = None;
    for seg in tokenize_path(rest)? {
        match seg {
            PathSeg::Name(name) => {
                let idx = resolve_field_index(parsed, cur_top, name)?;
                out.push(PATHOP_FIELD_IDX);
                out.extend_from_slice(&idx.to_be_bytes());
                cur_top = Some(name);
            }
            // Array ops have no meaning on the `@`/`$` envelope roots or in
            // EIP-712 `encodeData` (every member is exactly one word, no
            // dynamic tail). Refuse them here so a hazardous descriptor is
            // never EMITTED — making the device-side `render_array` decline
            // (which it does anyway) a SECOND line of defence, not the only
            // one. (The contract-calldata `#` root handles `[]` via the gated
            // `compile_array_all_path`.)
            PathSeg::ArrayIdx(_)
            | PathSeg::ArrayLast
            | PathSeg::ArrayAll
            | PathSeg::ArraySlice(_, _)
            | PathSeg::ArraySliceLast(_) => {
                return Err(
                    "array op (`[i]`/`[-1]`/`[]`/slice) is only supported as `<arg>.[]` on a \
                     contract-calldata (`#`) dynamic array — not on `@`/`$` envelope roots or \
                     EIP-712 typed-data members"
                        .to_string(),
                )
            }
        }
    }
    Ok(out)
}

/// Compile a contract-calldata `#.<field>[.<member>]` path into
/// `FieldIdx` ops whose **summed** args equal the field's ABI head-word
/// index. Each emitted `FieldIdx` is the head-word offset of the named
/// field among its siblings (top level, then optionally one static-tuple
/// level); the on-device walker sums them and reads that word.
///
/// Refuses — at build time, so a hazardous descriptor can never be pinned
/// — any path that:
///   * uses array indexing / slices (a dynamic-tail op the static-head
///     walker cannot follow);
///   * descends into a dynamic tuple (members live in the tail);
///   * terminates on a non-single-word type (dynamic, or a multi-word
///     array/tuple the renderer would misread as one 32-byte word);
///   * names a field absent from the function signature.
fn is_exact_router02_packed_v3_shape(parsed: &ParsedFormatKey) -> bool {
    let exact_signature = matches!(
        parsed.types_signature.as_str(),
        "exactInput((bytes,address,uint256,uint256))"
            | "exactOutput((bytes,address,uint256,uint256))"
    );
    let exact_top = parsed.top_names.len() == 1
        && parsed.top_names[0] == "params"
        && parsed.top_types.len() == 1
        && parsed.top_types[0] == "(bytes,address,uint256,uint256)";
    let exact_types = parsed.inner_types.get("params").is_some_and(|types| {
        types.len() == 4
            && types[0] == "bytes"
            && types[1] == "address"
            && types[2] == "uint256"
            && types[3] == "uint256"
    });
    exact_signature && exact_top && exact_types
}

fn compile_structured_contract_path(
    segs: &[PathSeg<'_>],
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
    is_token_path: bool,
    allow_packed_v3_path: bool,
) -> Result<(), String> {
    // A trailing `[]` (ArrayAll) renders EVERY element of a top-level dynamic
    // array — the only array op the renderer supports. Single-index `[i]` /
    // `[-1]` / slices stay refused below: showing one element hides the rest
    // (the array-tail-hiding WYSIWYS hazard). See the dynamic-array-walker
    // design doc for the safety argument.
    if matches!(segs.last(), Some(PathSeg::ArrayAll)) {
        return compile_array_all_path(&segs[..segs.len() - 1], parsed, out);
    }

    // tokenPath ONLY: a trailing extraction op (`[i]` / `[-1]` / `[a:b]` /
    // `[-N:]`) pulls a token IDENTIFICATION address out of a dynamic swap leg
    // (packed `bytes path`, or an `address[]`). For a rendered VALUE path this
    // is refused — the names loop below hits its `_ => reject` arm — which is
    // the load-bearing half of the tokenPath-only-slice invariant.
    if is_token_path {
        if let Some(last) = segs.last() {
            if matches!(
                last,
                PathSeg::ArrayIdx(_)
                    | PathSeg::ArrayLast
                    | PathSeg::ArraySlice(_, _)
                    | PathSeg::ArraySliceLast(_)
            ) {
                return compile_token_path_extraction(
                    &segs[..segs.len() - 1],
                    last,
                    parsed,
                    out,
                    allow_packed_v3_path,
                );
            }
        }
    }

    let mut names: Vec<&str> = Vec::with_capacity(segs.len());
    for seg in segs {
        match seg {
            PathSeg::Name(n) => names.push(n),
            _ => {
                return Err(
                    "contract calldata path uses array index/slice — unsupported \
                     (dynamic-tail access; only `<arg>.[]` render-all of a \
                      top-level dynamic array is supported)"
                        .to_string(),
                )
            }
        }
    }
    if names.is_empty() {
        return Err("contract calldata path names no field".to_string());
    }
    if names.len() > 2 {
        return Err(format!(
            "contract calldata path `{}` descends {} levels; only top-level and \
             one static-tuple level are supported",
            names.join("."),
            names.len()
        ));
    }

    let mut level_names: &[String] = &parsed.top_names;
    let mut level_types: &[String] = &parsed.top_types;
    for (depth, &name) in names.iter().enumerate() {
        let terminal = depth == names.len() - 1;
        let pos = level_names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| format!("path field `{name}` is not in the function signature"))?;

        // Head-word offset of this field among its preceding siblings.
        let mut slot: u32 = 0;
        for ty in &level_types[..pos] {
            slot = slot.saturating_add(head_slot_words(ty)?);
        }
        let arg: u16 = slot
            .try_into()
            .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
        out.push(PATHOP_FIELD_IDX);
        out.extend_from_slice(&arg.to_be_bytes());

        let this_ty = &level_types[pos];
        if terminal {
            match static_head_words(this_ty)? {
                HeadWidth::Words(1) => {}
                HeadWidth::Words(n) => {
                    return Err(format!(
                        "path field `{name}` has static type `{this_ty}` spanning {n} words; \
                         the trusted renderer reads a single 32-byte word — refusing to pin a \
                         descriptor that would display only part of it"
                    ))
                }
                HeadWidth::Dynamic => {
                    // C1: a dynamic `bytes`/`string` leaf. Its head slot holds an
                    // ABI offset word; emit FollowOffset so the device follows it
                    // to the length-prefixed blob in the tail (reading the SAME
                    // position the contract decodes). Dynamic ARRAYS are rendered
                    // via the `<arg>.[]` (`compile_array_all_path`) route, not
                    // here; a bare dynamic tuple is not a displayable leaf. A
                    // multi-tail format separately authenticates and validates
                    // the complete partition before resolving this path.
                    let t = this_ty.trim();
                    if t == "bytes" || t == "string" {
                        out.push(PATHOP_FOLLOW_OFFSET);
                    } else {
                        return Err(format!(
                            "path field `{name}` is dynamic (`{this_ty}`) and not a `bytes`/`string` \
                             leaf; dynamic arrays render via `<arg>.[]`, dynamic tuples are not a leaf"
                        ));
                    }
                }
            }
        } else {
            // Descend into a tuple. A STATIC tuple inlines its members in the
            // head, so the member's `FieldIdx` simply sums onto the tuple's head
            // slot. A DYNAMIC tuple needs its own local head width and tail
            // topology to prove member offsets/canonical end placement; compact
            // IR does not carry those facts, so C2 must fail closed.
            // A tuple ARRAY is also not a single tuple instance: descending
            // `calls.to` through `(...)[N] calls` would select only element 0
            // while the signature commits to every element. Reject only a
            // trailing array suffix on THIS type; an ordinary tuple may safely
            // contain an array member before the selected scalar because the
            // width-aware slot calculation already accounts for it.
            if find_last_array_open(this_ty.trim()).is_some() {
                return Err(format!(
                    "path descends through array-valued field `{name}` (`{this_ty}`); member descent would render only one element of the signed array"
                ));
            }
            if static_head_words(this_ty)? == HeadWidth::Dynamic {
                if !allow_packed_v3_path
                    || depth != 0
                    || pos != 0
                    || names.len() != 2
                    || !is_exact_router02_packed_v3_shape(parsed)
                {
                    return Err(format!(
                        "path descends through dynamic tuple `{name}` (`{this_ty}`); C2 tail topology is not represented in trusted IR"
                    ));
                }
                // Exact Router02 exception: the sole top-level dynamic tuple
                // begins at offset 32 and has the reviewed four-word local
                // head. Runtime re-proves both offsets and whole-tail framing
                // before any page is painted.
                out.push(PATHOP_FOLLOW_OFFSET);
            }
            let inner = parsed.inner_types.get(name).ok_or_else(|| {
                format!("path descends into `{name}`, which is not a parsed tuple argument")
            })?;
            level_names = parsed
                .inner_names
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            level_types = inner.as_slice();
        }
    }
    Ok(())
}

/// Compile a `tokenPath` that ends in an extraction op, resolving a token
/// address packed inside a dynamic swap leg. `name_segs` navigates to the
/// dynamic container (all `Name`s, ≤ 2 levels, same width-aware head-slot walk
/// as a normal path); `extract` is its terminal `[i]` / `[-1]` / `[a:b]` /
/// `[-N:]` op. Emits `FieldIdx… + FollowOffset + <extraction op>`.
///
/// Type discipline (build-time — a hazardous descriptor never compiles):
///   * `[a:b]` / `[-N:]` require the container to be dynamic `bytes`/`string`
///     and the slice width to be **exactly 20** (an address). Uniswap
///     `params.path.[0:20]` (input token) / `[-20:]` (output token). This
///     rejects paraswap's 32-byte word slices (`#.data.[292:324]`).
///   * `[i]` / `[-1]` require a dynamic `address[]` (element read as an
///     address). Uniswap V2 `swapExactTokensForTokens` `path.[0]` / `[-1]`.
/// The device resolver (`render::resolve::resolve_token_address`) re-validates
/// every bound at runtime and degrades any failure to raw-amount.
fn compile_token_path_extraction(
    name_segs: &[PathSeg<'_>],
    extract: &PathSeg<'_>,
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
    allow_packed_v3_path: bool,
) -> Result<(), String> {
    const ADDR_SLICE_LEN: u32 = 20;

    let mut names: Vec<&str> = Vec::with_capacity(name_segs.len());
    for seg in name_segs {
        match seg {
            PathSeg::Name(n) => names.push(n),
            _ => {
                return Err(
                    "tokenPath extraction op (`[i]`/`[-1]`/slice) must be the terminal segment"
                        .to_string(),
                )
            }
        }
    }
    if names.is_empty() {
        return Err("tokenPath extraction names no field".to_string());
    }
    if names.len() > 2 {
        return Err(format!(
            "tokenPath `{}` descends {} levels; only top-level and one tuple level are supported",
            names.join("."),
            names.len()
        ));
    }

    let mut level_names: &[String] = &parsed.top_names;
    let mut level_types: &[String] = &parsed.top_types;
    for (depth, &name) in names.iter().enumerate() {
        let terminal = depth == names.len() - 1;
        let pos = level_names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| format!("tokenPath field `{name}` is not in the function signature"))?;
        let mut slot: u32 = 0;
        for ty in &level_types[..pos] {
            slot = slot.saturating_add(head_slot_words(ty)?);
        }
        let arg: u16 = slot
            .try_into()
            .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
        out.push(PATHOP_FIELD_IDX);
        out.extend_from_slice(&arg.to_be_bytes());

        let this_ty = level_types[pos].trim();
        if !terminal {
            // Static tuple members stay inlined. Dynamic-tuple descent (C2)
            // needs tuple-local head/tail topology absent from compact IR.
            if find_last_array_open(this_ty).is_some() {
                return Err(format!(
                    "tokenPath descends through array-valued field `{name}` (`{this_ty}`); member descent would identify a token from only one signed element"
                ));
            }
            if static_head_words(this_ty)? == HeadWidth::Dynamic {
                if !allow_packed_v3_path
                    || depth != 0
                    || pos != 0
                    || names.len() != 2
                    || !is_exact_router02_packed_v3_shape(parsed)
                {
                    return Err(format!(
                        "tokenPath descends through dynamic tuple `{name}` (`{this_ty}`); C2 tail topology is not represented in trusted IR"
                    ));
                }
                out.push(PATHOP_FOLLOW_OFFSET);
            }
            let inner = parsed.inner_types.get(name).ok_or_else(|| {
                format!("tokenPath descends into `{name}`, which is not a parsed tuple argument")
            })?;
            level_names = parsed
                .inner_names
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            level_types = inner.as_slice();
            continue;
        }

        // Terminal: the container the extraction reads. Must be dynamic; follow
        // its head-slot offset to the tail region, then emit the extraction op.
        match extract {
            PathSeg::ArraySlice(_, _) | PathSeg::ArraySliceLast(_) => {
                if this_ty != "bytes" && this_ty != "string" {
                    return Err(format!(
                        "tokenPath byte-slice needs a dynamic `bytes`/`string` container, got `{this_ty}`"
                    ));
                }
                let (start, from_end) = match extract {
                    PathSeg::ArraySlice(a, b) => {
                        let len = b.checked_sub(*a).filter(|l| *l > 0).ok_or_else(|| {
                            format!("tokenPath slice `[{a}:{b}]` is empty or reversed")
                        })?;
                        if len != ADDR_SLICE_LEN {
                            return Err(format!(
                                "tokenPath slice `[{a}:{b}]` is {len} bytes; only a 20-byte address \
                                 slice is accepted (packed-path token id)"
                            ));
                        }
                        (*a, false)
                    }
                    PathSeg::ArraySliceLast(n) => {
                        if *n != ADDR_SLICE_LEN {
                            return Err(format!(
                                "tokenPath tail slice `[-{n}:]` is {n} bytes; only a 20-byte address \
                                 slice is accepted"
                            ));
                        }
                        (0u32, true)
                    }
                    _ => unreachable!(),
                };
                let start_u16: u16 = start
                    .try_into()
                    .map_err(|_| format!("tokenPath slice start {start} overflows u16"))?;
                out.push(PATHOP_FOLLOW_OFFSET);
                out.push(PATHOP_ARRAY_SLICE);
                out.extend_from_slice(&start_u16.to_be_bytes());
                out.extend_from_slice(&(ADDR_SLICE_LEN as u16).to_be_bytes());
                out.push(u8::from(from_end));
            }
            PathSeg::ArrayIdx(_) | PathSeg::ArrayLast => {
                // Dynamic `address[]` — element read as a 32-byte word, low 20 =
                // address. Reject fixed-length arrays and non-address elements.
                let open = find_last_array_open(this_ty).ok_or_else(|| {
                    format!("tokenPath index needs a dynamic `address[]`, got `{this_ty}`")
                })?;
                if parse_fixed_array_len(&this_ty[open..])?.is_some() {
                    return Err(format!(
                        "tokenPath index needs a DYNAMIC array (`T[]`), got fixed `{this_ty}`"
                    ));
                }
                let base = this_ty[..open].trim();
                if base != "address" {
                    return Err(format!(
                        "tokenPath index element is `{base}`, not `address` — refusing to read a \
                         non-address word as a token id"
                    ));
                }
                out.push(PATHOP_FOLLOW_OFFSET);
                match extract {
                    PathSeg::ArrayIdx(i) => {
                        let i_u16: u16 = (*i)
                            .try_into()
                            .map_err(|_| format!("tokenPath index {i} overflows u16"))?;
                        out.push(PATHOP_ARRAY_IDX);
                        out.extend_from_slice(&i_u16.to_be_bytes());
                    }
                    PathSeg::ArrayLast => out.push(PATHOP_ARRAY_LAST),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!("extract is one of the four op variants"),
        }
    }
    Ok(())
}

/// Compile a `<arg>.[]` path that renders EVERY element of a top-level
/// dynamic array of static primitives. Emits `FieldIdx(offset-word-slot) +
/// ArrayAll`. Refuses unless the array is a top-level `T[]` (T a static
/// primitive). The on-device renderer either enforces legacy sole-tail framing
/// or obtains this array's exact interval from an authenticated multi-tail
/// partition. Single-index `[i]` / `[-1]` / slices stay refused (they would
/// hide the array's other elements).
fn compile_array_all_path(
    name_segs: &[PathSeg<'_>],
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    // The element selector applies to a single TOP-LEVEL argument only.
    let name = match name_segs {
        [PathSeg::Name(n)] => *n,
        _ => {
            return Err(
                "array `[]` path must be a single top-level argument (e.g. `amounts.[]`)"
                    .to_string(),
            )
        }
    };
    let pos = parsed
        .top_names
        .iter()
        .position(|n| n == name)
        .ok_or_else(|| {
            format!("array `[]` path field `{name}` is not in the function signature")
        })?;
    let this_ty = &parsed.top_types[pos];
    if dynamic_array_static_elem(this_ty).is_none() {
        return Err(format!(
            "array `[]` path field `{name}` (`{this_ty}`) must be a dynamic array of a static \
             primitive (uintN/intN/address/bool/bytesN); nested / dynamic / tuple element arrays \
             are unsupported"
        ));
    }
    // Offset-word slot = sum of preceding args' head widths (the array's one
    // offset word lives here, in the static head).
    let mut slot: u32 = 0;
    for ty in &parsed.top_types[..pos] {
        slot = slot.saturating_add(head_slot_words(ty)?);
    }
    let arg: u16 = slot
        .try_into()
        .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
    out.push(PATHOP_FIELD_IDX);
    out.extend_from_slice(&arg.to_be_bytes());
    out.push(PATHOP_ARRAY_ALL);
    Ok(())
}

/// `Some(elem_type)` iff `ty` is a dynamic array `T[]` whose element `T` is a
/// static primitive (one 32-byte word, not a tuple or nested array).
fn dynamic_array_static_elem(ty: &str) -> Option<&str> {
    let ty = ty.trim();
    let base = ty.strip_suffix("[]")?;
    if base.is_empty() || base.starts_with('(') || base.contains('[') {
        return None; // tuple element or nested array
    }
    match static_head_words(base) {
        Ok(HeadWidth::Words(1)) => Some(base),
        _ => None,
    }
}

/// Total ABI static head width of a format, in 32-byte words — the number
/// of head words the on-device renderer must see before it walks any
/// field. For contract calldata this is the sum of every top-level
/// argument's head width (dynamic args contribute their one offset word);
/// for EIP-712 `encodeData` every top-level member is exactly one word.
/// The device truncates the body to this many words so an out-of-head
/// slot (a malformed descriptor's read into the dynamic tail) is rejected
/// rather than silently rendered.
fn format_static_head_words(context_kind: u8, parsed: &ParsedFormatKey) -> Result<u16, String> {
    let words: u32 = if context_kind == CTX_CONTRACT {
        let mut total = 0u32;
        for ty in &parsed.top_types {
            total = total.saturating_add(head_slot_words(ty)?);
        }
        total
    } else {
        parsed.top_names.len() as u32
    };
    u16::try_from(words).map_err(|_| format!("static head {words} words overflows u16"))
}

/// Map a declared name segment to its 2-byte BE field ordinal. For the first
/// name after the root we use `parsed.top_names`; subsequent names use the
/// parsed tuple member list. Unknown names are a hard error: the device has no
/// authenticated runtime name table, and truncating a name hash to 16 bits can
/// alias a real ordinal (for example a bogus EIP-712 tokenPath aliasing member
/// zero) while presenting the wrong token identity.
fn resolve_field_index(
    parsed: &ParsedFormatKey,
    cur_top: Option<&str>,
    name: &str,
) -> Result<u16, String> {
    let names: &[String] = if let Some(top) = cur_top {
        parsed
            .inner_names
            .get(top)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    } else {
        &parsed.top_names
    };
    if let Some(pos) = names.iter().position(|n| n == name) {
        return u16::try_from(pos).map_err(|_| format!("field index {pos} > u16::MAX"));
    }
    let scope = cur_top
        .map(|parent| format!("the parsed members of `{parent}`"))
        .unwrap_or_else(|| "the format's top-level members".to_string());
    Err(format!("path field `{name}` is not in {scope}"))
}

enum PathSeg<'a> {
    Name(&'a str),
    // Array index / slice ops. For a rendered VALUE path these are still
    // REFUSED (single-index / slice would hide an array's other elements — the
    // array-tail-hiding WYSIWYS hazard). They are accepted ONLY as the terminal
    // op of a `tokenPath` (token IDENTIFICATION, not a shown value) — see
    // `compile_structured_contract_path`'s `is_token_path` branch.
    ArrayIdx(u32),        // `[i]`   — element i of a `T[]`
    ArrayLast,            // `[-1]`  — last element of a `T[]`
    ArrayAll,             // `[]`    — render every element (value path)
    ArraySlice(u32, u32), // `[a:b]` — byte slice `[a, b)` of a dynamic `bytes`
    ArraySliceLast(u32),  // `[-N:]` — last N bytes of a dynamic `bytes`
}

fn tokenize_path(rest: &str) -> Result<Vec<PathSeg<'_>>, String> {
    let mut out = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
            }
            b'[' => {
                // Find matching ].
                let close = bytes[i..]
                    .iter()
                    .position(|&b| b == b']')
                    .ok_or_else(|| format!("unmatched '[' in path `{rest}`"))?;
                let body = &rest[i + 1..i + close];
                let body_trim = body.trim();
                if body_trim.is_empty() {
                    out.push(PathSeg::ArrayAll);
                } else if body_trim == "-1" || body_trim == "last" {
                    out.push(PathSeg::ArrayLast);
                } else if let Some((a, b)) = body_trim.split_once(':') {
                    let a = a.trim();
                    let b = b.trim();
                    if let Some(neg) = a.strip_prefix('-') {
                        // `[-N:]` — last N bytes of a dynamic `bytes` (the tail
                        // must be open; `[-N:M]` is not a shape any descriptor uses).
                        if !b.is_empty() {
                            return Err(format!(
                                "negative-start slice `[{body_trim}]` must be open-ended (`[-N:]`)"
                            ));
                        }
                        let n: u32 = neg
                            .parse()
                            .map_err(|_| format!("slice tail count `{neg}` not u32"))?;
                        out.push(PathSeg::ArraySliceLast(n));
                    } else {
                        let a: u32 = a
                            .parse()
                            .map_err(|_| format!("slice start `{a}` not u32"))?;
                        let b: u32 = b.parse().map_err(|_| format!("slice end `{b}` not u32"))?;
                        out.push(PathSeg::ArraySlice(a, b));
                    }
                } else if let Ok(n) = body_trim.parse::<u32>() {
                    out.push(PathSeg::ArrayIdx(n));
                } else {
                    return Err(format!(
                        "unrecognized array segment `[{body_trim}]` in `{rest}`"
                    ));
                }
                i += close + 1;
            }
            b if (b.is_ascii_alphanumeric() || b == b'_') => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                out.push(PathSeg::Name(&rest[start..i]));
            }
            other => {
                return Err(format!(
                    "unexpected byte 0x{:02x} ({:?}) in path `{rest}`",
                    other, other as char
                ))
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// IR builder.
// ─────────────────────────────────────────────────────────────────────

fn build_ir(
    context_kind: u8,
    chain_id: u64,
    contract: [u8; 20],
    domain_separator: &[u8; 32],
    ctx: &CompileCtx,
    pool: &[u8],
    formats: &[u8],
) -> Result<Vec<u8>, String> {
    let pool_len = pool.len();
    let formats_len = formats.len();
    if pool_len > u16::MAX as usize {
        return Err(format!("pool_len {pool_len} > u16::MAX"));
    }
    if formats_len > u16::MAX as usize {
        return Err(format!("formats_len {formats_len} > u16::MAX"));
    }
    let metadata_off = HEADER_LEN as u16;
    let formats_off = (HEADER_LEN + pool_len) as u16;

    let mut buf = vec![0u8; HEADER_LEN];
    buf[0] = SCHEMA_VER;
    buf[1] = context_kind;
    buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
    buf[10..30].copy_from_slice(&contract);
    buf[30..62].copy_from_slice(&ctx.descriptor_hash);
    buf[62..94].copy_from_slice(domain_separator);

    // Owner + contract_name: NUL-padded, ≤ 15 + NUL.
    write_padded_ascii(&mut buf[94..94 + OWNER_FIELD_LEN], &ctx.owner)?;
    write_padded_ascii(
        &mut buf[110..110 + CONTRACT_NAME_FIELD_LEN],
        &ctx.contract_name,
    )?;

    buf[126..128].copy_from_slice(&metadata_off.to_be_bytes());
    buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
    buf[130..132].copy_from_slice(&(pool_len as u16).to_be_bytes());
    buf[132..134].copy_from_slice(&(formats_len as u16).to_be_bytes());

    buf.extend_from_slice(pool);
    buf.extend_from_slice(formats);

    Ok(buf)
}

fn write_padded_ascii(slot: &mut [u8], s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    if bytes.len() >= slot.len() {
        return Err(format!(
            "ASCII field too long ({} >= {} including NUL)",
            bytes.len(),
            slot.len()
        ));
    }
    if !bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(format!("ASCII field has non-printable byte(s): {s:?}"));
    }
    slot.fill(0);
    slot[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Enum tables.
// ─────────────────────────────────────────────────────────────────────

fn encode_enum_table(table: &serde_json::Value) -> Result<Vec<u8>, String> {
    let map = table
        .as_object()
        .ok_or_else(|| "enum table must be an object".to_string())?;
    if map.len() > 255 {
        return Err(format!("enum has {} entries > 255", map.len()));
    }
    if map.is_empty() {
        return Err("enum table must contain at least one entry".to_string());
    }
    let mut entries: Vec<(u64, String)> = Vec::with_capacity(map.len());
    let mut display_labels = BTreeSet::new();
    for (k, v) in map {
        let key: u64 = k
            .parse()
            .map_err(|_| format!("enum key `{k}` must be a non-negative integer"))?;
        let val = v
            .as_str()
            .ok_or_else(|| format!("enum value for `{k}` must be a string"))?;
        let val = clean_ascii_truncated(val, ENUM_DISPLAY_BYTES);
        if !label_has_visible_glyph(val.as_bytes()) || val.ends_with(' ') {
            return Err(format!(
                "enum value for `{k}` is empty, blank, or ends in ambiguous display padding"
            ));
        }
        if !display_labels.insert(val.clone()) {
            return Err(format!(
                "enum value for `{k}` collides with another label after printable-ASCII sanitization and the {ENUM_DISPLAY_BYTES}-byte device display cap"
            ));
        }
        entries.push((key, val));
    }
    entries.sort_by_key(|(k, _)| *k);

    let mut out = Vec::with_capacity(1 + entries.len() * 12);
    out.push(entries.len() as u8);
    for (k, v) in entries {
        out.extend_from_slice(&k.to_be_bytes()); // 8 B BE
        out.push(v.len() as u8);
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// EIP-712 domain separator.
// ─────────────────────────────────────────────────────────────────────

fn compute_domain_separator(d: &Eip712Domain) -> Result<[u8; 32], String> {
    // EIP-712 §`EIP712Domain` typehash is computed from only the
    // *present* fields. We assemble the field list and the
    // corresponding encoded values, then keccak both.
    let mut typestr = String::from("EIP712Domain(");
    let mut encoded: Vec<u8> = Vec::new();
    let mut first = true;
    let push_field = |t: &str,
                      name: &str,
                      encoded_value: [u8; 32],
                      typestr: &mut String,
                      encoded: &mut Vec<u8>,
                      first: &mut bool| {
        if !*first {
            typestr.push(',');
        }
        typestr.push_str(t);
        typestr.push(' ');
        typestr.push_str(name);
        encoded.extend_from_slice(&encoded_value);
        *first = false;
    };
    if let Some(name) = &d.name {
        push_field(
            "string",
            "name",
            keccak256(name.as_bytes()),
            &mut typestr,
            &mut encoded,
            &mut first,
        );
    }
    if let Some(version) = &d.version {
        push_field(
            "string",
            "version",
            keccak256(version.as_bytes()),
            &mut typestr,
            &mut encoded,
            &mut first,
        );
    }
    if let Some(cid) = d.chain_id {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&cid.to_be_bytes());
        push_field(
            "uint256",
            "chainId",
            buf,
            &mut typestr,
            &mut encoded,
            &mut first,
        );
    }
    if let Some(addr) = &d.verifying_contract {
        let a = parse_address(addr)?;
        let mut buf = [0u8; 32];
        buf[12..32].copy_from_slice(&a);
        push_field(
            "address",
            "verifyingContract",
            buf,
            &mut typestr,
            &mut encoded,
            &mut first,
        );
    }
    if let Some(salt) = &d.salt {
        let s = parse_hex32(salt)?;
        push_field("bytes32", "salt", s, &mut typestr, &mut encoded, &mut first);
    }
    typestr.push(')');

    let typehash = keccak256(typestr.as_bytes());
    let mut preimage = Vec::with_capacity(32 + encoded.len());
    preimage.extend_from_slice(&typehash);
    preimage.extend_from_slice(&encoded);
    Ok(keccak256(&preimage))
}

// ─────────────────────────────────────────────────────────────────────
// JCS canonicalization (RFC 8785 subset — integers / strings only).
// ─────────────────────────────────────────────────────────────────────

const MAX_JCS_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

fn jcs_canonicalize(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out = String::with_capacity(256);
    jcs_render(v, &mut out)?;
    Ok(out.into_bytes())
}

fn jcs_render(v: &serde_json::Value, out: &mut String) -> Result<(), String> {
    match v {
        serde_json::Value::Null => {
            out.push_str("null");
            Ok(())
        }
        serde_json::Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        serde_json::Value::Number(n) => {
            // JCS requires shortest IEEE-754 form for floats. Real
            // ERC-7730 descriptors use only integers and string values. Keep
            // this intentionally smaller subset interoperable with the
            // ECMAScript parser used by external ERC-8176 auditors: integers
            // outside the exact safe range would otherwise be rounded before
            // their JCS hash while serde_json preserves their wider spelling.
            if let Some(u) = n.as_u64() {
                if u > MAX_JCS_SAFE_INTEGER {
                    return Err(format!(
                        "JCS: integer {u} exceeds the exact IEEE-754 safe range (+/-{MAX_JCS_SAFE_INTEGER})"
                    ));
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i < -(MAX_JCS_SAFE_INTEGER as i64) {
                    return Err(format!(
                        "JCS: integer {i} exceeds the exact IEEE-754 safe range (+/-{MAX_JCS_SAFE_INTEGER})"
                    ));
                }
                out.push_str(&i.to_string());
            } else {
                return Err(format!(
                    "JCS: float numbers not supported in Phase 2 (got {n})"
                ));
            }
            Ok(())
        }
        serde_json::Value::String(s) => {
            jcs_render_string(s, out);
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        serde_json::Value::Object(map) => {
            // RFC 8785 sorts object keys by UTF-16 code units. For pure
            // ASCII keys this is identical to byte order, which is what
            // our seed corpus uses. We collect & sort by UTF-16 in case
            // a future descriptor ships non-ASCII keys.
            let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            keys.sort_by(|a, b| utf16_codeunit_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render_string(k, out);
                out.push(':');
                jcs_render(&map[*k], out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

fn jcs_render_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn utf16_codeunit_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ai = a.encode_utf16();
    let bi = b.encode_utf16();
    ai.cmp(bi)
}

// ─────────────────────────────────────────────────────────────────────
// Policy enforcement.
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// `includes` resolution (Phase 5, item 2).
//
// The ERC-7730 registry uses `"includes"` references so the
// templated permit / EIP-712 common entries don't duplicate the
// boilerplate. We resolve these against a local mirror of the
// registry passed in via `--registry-root <dir>`. Three forms are
// supported:
//
//   1. Relative file path           — `./templates/permit.json`
//   2. Registry-relative path       — `registry/templates/permit.json`
//   3. GitHub URL                   — `https://github.com/ethereum/
//      clear-signing-erc7730-registry/blob/<sha>/templates/permit.json`
//      → strip the host + branch prefix and resolve as a relative
//      path under `registry_root`.
//
// Include authority is exactly the corpus covered by the checked-in receipt:
// canonical non-fixture `.json` files below `registry/` or `ercs/`. Merely
// remaining below `registry_root` is insufficient because root-level files,
// fixture trees, and non-JSON files are deliberately absent from that receipt.
// ─────────────────────────────────────────────────────────────────────

fn resolve_include_path(
    registry_root: &Path,
    descriptor_path: &Path,
    include_ref: &str,
) -> Result<PathBuf, String> {
    let registry_root = registry_root
        .canonicalize()
        .map_err(|e| format!("canonicalize registry-root: {e}"))?;

    let candidate: PathBuf = if let Some(stripped) = include_ref.strip_prefix("https://github.com/")
    {
        // `<owner>/<repo>/blob/<ref>/<path>` or
        // `<owner>/<repo>/raw/<ref>/<path>` — strip the first four
        // segments to get the path inside the registry.
        let parts: Vec<&str> = stripped.splitn(5, '/').collect();
        if parts.len() < 5 {
            return Err(format!(
                "github URL include `{include_ref}` has too few path segments"
            ));
        }
        registry_root.join(parts[4])
    } else {
        // Any other reference (`./foo.json`, `../foo.json`, or a bare
        // sibling filename like `common-AggregationRouterV4.json` — the
        // registry's actual convention) resolves against the descriptor's
        // OWN directory. The outside-registry-root guard below still bounds
        // the result, so a `../../../etc/passwd` include is refused.
        descriptor_path
            .parent()
            .ok_or_else(|| "descriptor path has no parent".to_string())?
            .join(include_ref)
    };

    let candidate_metadata = fs::symlink_metadata(&candidate)
        .map_err(|e| format!("inspect include `{include_ref}`: {e}"))?;
    if candidate_metadata.file_type().is_symlink() || !candidate_metadata.is_file() {
        return Err(format!(
            "include `{include_ref}` must name a regular non-symlink corpus file"
        ));
    }

    let canonical = candidate
        .canonicalize()
        .map_err(|e| format!("canonicalize include `{include_ref}`: {e}"))?;
    validate_receipted_include_path(&registry_root, &canonical, include_ref)?;
    Ok(canonical)
}

fn validate_receipted_include_path(
    registry_root: &Path,
    canonical: &Path,
    include_ref: &str,
) -> Result<(), String> {
    let relative = canonical.strip_prefix(registry_root).map_err(|_| {
        format!("include `{include_ref}` resolves outside registry-root — refusing")
    })?;
    let relative_text = relative
        .to_str()
        .ok_or_else(|| format!("include `{include_ref}` resolves to a non-UTF-8 corpus path"))?;
    let mut components = relative.components();
    let top = components.next().and_then(|component| match component {
        std::path::Component::Normal(value) => value.to_str(),
        _ => None,
    });
    let filename = relative
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("include `{include_ref}` has no canonical UTF-8 filename"))?;
    if !matches!(top, Some("registry" | "ercs"))
        || !filename.ends_with(".json")
        || relative
            .components()
            .any(|component| component.as_os_str() == "tests")
        || filename.contains(".tests.")
    {
        return Err(format!(
            "include `{include_ref}` resolves outside the receipted registry/ercs JSON corpus: `{relative_text}`"
        ));
    }
    Ok(())
}

/// Deep-merge `over` on top of `base`. For object-typed leaves the
/// keys merge recursively; for any non-object leaf `over` wins. This
/// matches the semantics that the ERC-7730 registry expects from its
/// `includes` resolution (the descriptor is the "over" document; the
/// template is the "base").
fn merge_descriptors(base: serde_json::Value, over: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match (base, over) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = if let Some(existing) = b.remove(&k) {
                    merge_descriptors(existing, v)
                } else {
                    v
                };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        // For non-objects, `over` wins.
        (_, over) => over,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Review file (vendor-readable summary).
// ─────────────────────────────────────────────────────────────────────

/// Short display name for a `FormatOp` discriminant, for the review file's
/// per-field breakdown. Mirrors `pqsigner_erc7730::ir::FormatOp` — kept as a
/// flat table (not `FormatOp::try_from(..).map(|o| format!("{o:?}"))`) so an
/// unknown/out-of-range op renders visibly as `?<hex>` rather than eliding.
fn fmt_op_name(op: u8) -> &'static str {
    match op {
        0x01 => "raw",
        0x02 => "amount",
        0x03 => "tokenAmount",
        0x04 => "nftName",
        0x05 => "date",
        0x06 => "duration",
        0x07 => "addressName",
        0x08 => "enum",
        0x09 => "unit",
        0x0A => "calldata",
        0x0B => "chainId",
        0x0C => "tokenTicker",
        0x0D => "interopAddressName",
        0x0E => "encrypted",
        0x0F => "uniswapV3Path",
        _ => "?unknown",
    }
}

/// Bucket a tolerant-build skip reason into a coarse category, for the
/// committed review file's skip roll-up. Mirrors (and corrects) the xtask
/// scanner's `skip_category`: the completeness lint is checked **before**
/// the attestation/policy bucket, because a completeness message that names
/// a `visible:"never"` / hidden field would otherwise be mis-bucketed as an
/// attestation-policy skip (review finding, xtask/src/main.rs:1417).
pub fn review_skip_category(msg: &str) -> &'static str {
    let m = msg;
    if m.contains("UNSCANNED") {
        "unscanned (filename convention — review 2.3)"
    } else if m.contains("duplicate (chain_id=") {
        "duplicate leaf (deduped)"
    } else if m.contains("no compilable formats") {
        // Umbrella reason when EVERY format in a descriptor failed; the
        // per-format blocker is not surfaced today (see the note in
        // `compile_descriptor`). Bucketed separately so it doesn't swamp
        // "other" and so a resync that flips a whole descriptor dead is
        // visible.
        "whole-descriptor dead (all formats blocked)"
    } else if m.contains("completeness")
        || m.contains("not covered")
        || m.contains("must cover")
        || m.contains("uncovered")
        || m.contains("hidden")
        || m.contains("visible")
    {
        "completeness lint (un-displayed field)"
    } else if m.contains("array index") || m.contains("array slice") || m.contains("ArrayIdx") {
        "array-path (needs value-path slice/index resolver)"
    } else if m.contains("dynamic tuple") || m.contains("is dynamic") || m.contains("calldata tail")
    {
        "dynamic-ABI-type (needs walker)"
    } else if m.contains("spanning") && m.contains("words") {
        "multi-word static field (>32B)"
    } else if m.contains("includes") {
        "includes-unresolved"
    } else if m.contains("unresolved $ref") || m.contains("definition") {
        "unresolved $ref / definition"
    } else if m.contains("nested calldata") || m.contains("encrypted") {
        "unsupported formatter (nested-calldata / encrypted)"
    } else if m.contains("nft") {
        "unsupported formatter (nft)"
    } else if m.contains("enum") {
        "enum issue"
    } else if m.contains("MAX_IR_LEN")
        || m.contains("exceeds")
        || m.contains("too large")
        || m.contains("too long")
    {
        "IR too large (>4KiB)"
    } else if m.contains("unconsumed") || m.contains("unknown key") || m.contains("unrecognized") {
        "unmodeled descriptor key"
    } else if m.contains("policy") || m.contains("attest") {
        "attestation policy"
    } else if m.starts_with("schema")
        || m.starts_with("parse")
        || m.contains("schema:")
        || m.contains("missing field")
    {
        "schema / parse"
    } else if m.contains("selector")
        || m.contains("signature")
        || m.contains("encodeType")
        || m.contains("primary")
    {
        "selector / type-signature"
    } else {
        "other"
    }
}

fn review_ascii(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &byte in bytes {
        for escaped in std::ascii::escape_default(byte) {
            out.push(char::from(escaped));
        }
    }
    out.push('"');
    out
}

fn review_pool_entry<'a>(ir: &'a Erc7730Ir<'a>, off: u16) -> Result<&'a [u8], String> {
    if off == 0 {
        return Ok(&[]);
    }
    let off = off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or_else(|| "pool offset is outside the authenticated IR".to_string())?
        as usize;
    ir.pool
        .get(off + 1..off + 1 + len)
        .ok_or_else(|| "length-prefixed pool entry is truncated".to_string())
}

fn review_visibility_name(visibility: pqsigner_erc7730::ir::Visibility) -> &'static str {
    use pqsigner_erc7730::ir::Visibility;
    match visibility {
        Visibility::Always => "always",
        Visibility::Never => "never",
        Visibility::Optional => "optional",
        Visibility::IfNotIn => "ifNotIn",
        Visibility::MustMatch => "mustMatch",
    }
}

/// Canonical decoded view of every parameter meaning the device parser exposes.
/// The review line also carries the exact raw TLV bytes, so an omitted decoder
/// field cannot erase the authenticated identity of a newly added tag.
fn review_param_semantics(
    params: &pqsigner_erc7730::render::params::ParamSet<'_>,
) -> Result<String, String> {
    let mut parts = Vec::new();
    if let Some(path) = params.token_path {
        parts.push(format!("tokenPath=0x{}", hex::encode(path)));
    }
    if let Some(token) = params.token {
        parts.push(format!("token=0x{}", hex::encode(token)));
    }
    if let Some(threshold) = params.threshold {
        parts.push(format!("threshold=0x{}", hex::encode(threshold)));
    }
    if let Some(message) = params.message {
        parts.push(format!("message={}", review_ascii(message)));
    }
    if let Some(types) = params.addr_types {
        parts.push(format!("addressTypes=0x{types:02x}"));
    }
    if let Some(sources) = params.addr_sources {
        parts.push(format!("addressSources=0x{sources:02x}"));
    }
    if let Some(encoding) = params.date_encoding {
        parts.push(format!("dateEncoding={encoding}"));
    }
    if let Some(enum_ref) = params.enum_ref {
        parts.push(format!("enumRef={enum_ref}"));
    }
    if let Some(decimals) = params.decimals {
        parts.push(format!("decimals={decimals}"));
    }
    if let Some(base) = params.base {
        parts.push(format!("base={}", review_ascii(base)));
    }
    if let Some(prefix) = params.prefix {
        parts.push(format!("prefix={prefix}"));
    }
    if let Some(suffix) = params.suffix {
        parts.push(format!("suffix={}", review_ascii(suffix)));
    }
    if let Some(selector) = params.nested_selector {
        parts.push(format!("nestedSelector=0x{}", hex::encode(selector)));
    }
    if let Some(callee) = params.nested_callee {
        parts.push(format!("nestedCallee=0x{}", hex::encode(callee)));
    }
    if let Some(label) = params.fallback_label {
        parts.push(format!("fallbackLabel={}", review_ascii(label)));
    }
    parts.push(format!(
        "visibility={}",
        review_visibility_name(params.visibility)
    ));
    if let Some(values) = params.visibility_values {
        parts.push(format!("visibilityValues=0x{}", hex::encode(values)));
    }
    if let Some(value) = params.const_value {
        parts.push(format!("constValue={}", review_ascii(value)));
    }
    if let Some(nested) = params.nested_struct {
        parts.push(format!("nestedStruct=0x{}", hex::encode(nested)));
    }
    if let Some(addresses) = params.native_currency_addresses {
        let members = addresses
            .chunks_exact(pqsigner_erc7730::render::params::NATIVE_CURRENCY_ADDRESS_LEN)
            .map(|address| format!("0x{}", hex::encode(address)))
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("nativeCurrency=[{members}]"));
    }
    if let Some(kind) = params.dynamic_kind {
        let name = match kind {
            pqsigner_erc7730::render::params::DYNAMIC_KIND_STRING => "string",
            pqsigner_erc7730::render::params::DYNAMIC_KIND_BYTES => "bytes",
            _ => "unknown",
        };
        parts.push(format!("dynamicKind={name}(0x{kind:02x})"));
    }
    if params.exact_empty_bytes {
        parts.push("exactEmptyBytes=true".to_string());
    }
    if let Some(ordinal) = params.eip712_string_preimage_ordinal {
        parts.push(format!("eip712StringPreimageOrdinal={ordinal}"));
    }
    if let Some(collection) = params.nft_collection {
        parts.push(format!("nftCollection=0x{}", hex::encode(collection)));
    }
    if let Some(path) = params.nft_collection_path {
        parts.push(format!("nftCollectionPath=0x{}", hex::encode(path)));
    }
    if let Some(program) = params.interpolated_intent {
        let count = program.substitution_count();
        let mut literals = Vec::with_capacity(count as usize + 1);
        let mut ordinals = Vec::with_capacity(count as usize);
        for slot in 0..count {
            literals.push(review_ascii(
                program
                    .literal(slot)
                    .map_err(|e| format!("interpolation literal {slot}: {e:?}"))?,
            ));
            ordinals.push(
                program
                    .field_ordinal(slot)
                    .map_err(|e| format!("interpolation ordinal {slot}: {e:?}"))?
                    .to_string(),
            );
        }
        literals.push(review_ascii(
            program
                .literal(count)
                .map_err(|e| format!("interpolation final literal: {e:?}"))?,
        ));
        parts.push(format!(
            "interpolatedIntent={{version={},count={},literals=[{}],ordinals=[{}]}}",
            pqsigner_erc7730::render::params::INTERPOLATED_INTENT_VERSION,
            count,
            literals.join(","),
            ordinals.join(","),
        ));
    }
    if let Some(kind) = params.terminal_kind {
        let name = match kind {
            TerminalKind::Unsigned => "unsigned",
            TerminalKind::Signed => "signed",
            TerminalKind::Address => "address",
            TerminalKind::Bool => "bool",
            TerminalKind::FixedBytes => "fixedBytes",
            TerminalKind::DynamicString => "dynamicString",
            TerminalKind::DynamicBytes => "dynamicBytes",
            TerminalKind::ConstantText => "constantText",
            TerminalKind::NestedStruct => "nestedStruct",
            TerminalKind::Eip712StringHashWord => "eip712StringHashWord",
        };
        parts.push(format!("terminalKind={name}(0x{:02x})", kind as u8));
    }
    if let Some(width) = params.integer_width_bytes {
        parts.push(format!("integerWidthBytes={width}"));
    }
    if let Some(addresses) = params.sender_addresses {
        let members = addresses
            .chunks_exact(pqsigner_erc7730::render::params::SENDER_ADDRESS_LEN)
            .map(|address| format!("0x{}", hex::encode(address)))
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("senderAddress=[{members}]"));
    }
    if let Some(guard) = params.word_guard {
        let operation = match guard.mode() {
            pqsigner_erc7730::render::params::WORD_GUARD_EQ => "eq",
            pqsigner_erc7730::render::params::WORD_GUARD_NE => "ne",
            _ => "unknown",
        };
        parts.push(format!(
            "wordGuard={operation}(0x{})",
            hex::encode(guard.expected())
        ));
    }
    Ok(format!("{{{}}}", parts.join(",")))
}

/// Decode one leaf's IR into a format/field breakdown (intent + canonical raw
/// path/TLV bytes + decoded semantics) plus a count of *degraded* fields —
/// `raw`-op fields with an empty label, the signature of a descriptor whose
/// author-intended formatting was silently lost (e.g. a dropped `$ref`; review
/// finding 1.1). Returns `(lines, field_count, degraded_count)`. Never panics: a
/// parse failure yields a visible error line so the catalogue still reconciles.
fn review_field_breakdown(ir_bytes: &[u8]) -> (Vec<String>, usize, usize) {
    let mut lines = Vec::new();
    let mut n_fields = 0usize;
    let mut n_degraded = 0usize;
    let ir = match Erc7730Ir::parse(ir_bytes) {
        Ok(ir) => ir,
        Err(e) => {
            lines.push(format!("         · <IR PARSE ERROR: {e:?}>"));
            return (lines, 0, 0);
        }
    };
    for fmt in ir.format_iter() {
        let Ok(fmt) = fmt else {
            lines.push("         · <malformed format entry>".to_string());
            break;
        };
        lines.push(format!(
            "         · format [0x{}] intent={} intent_raw=0x{} static_head_words={} nested_descent_count={} string_preimage_count={}",
            hex::encode(fmt.selector),
            review_ascii(fmt.intent),
            hex::encode(fmt.intent),
            fmt.static_head_words,
            fmt.nested_descent_count,
            fmt.string_preimage_count,
        ));
        for (field_ordinal, field) in fmt.fields().enumerate() {
            let Ok(field) = field else {
                lines.push("         · <malformed field entry>".to_string());
                break;
            };
            n_fields += 1;
            let degraded = field.format_op == 0x01 && field.label.is_empty();
            if degraded {
                n_degraded += 1;
            }
            let path = match ir.path_bytes(field.path_off) {
                Ok(path) => path,
                Err(e) => {
                    lines.push(format!(
                        "         ·   field[{field_ordinal}] <PATH ERROR: {e:?}>"
                    ));
                    continue;
                }
            };
            let raw_params = match review_pool_entry(&ir, field.param_off) {
                Ok(raw) => raw,
                Err(e) => {
                    lines.push(format!(
                        "         ·   field[{field_ordinal}] <PARAM ERROR: {e}>"
                    ));
                    continue;
                }
            };
            let decoded_params = match pqsigner_erc7730::render::params::parse(&ir, field.param_off)
                .map_err(|e| format!("{e:?}"))
                .and_then(|params| review_param_semantics(&params))
            {
                Ok(decoded) => decoded,
                Err(e) => format!("<PARAM DECODE ERROR: {e}>"),
            };
            lines.push(format!(
                "         ·   field[{field_ordinal}] op={:<12} label={} path=0x{} params_tlv=0x{} params={}{}",
                fmt_op_name(field.format_op),
                review_ascii(field.label),
                hex::encode(path),
                hex::encode(raw_params),
                decoded_params,
                if degraded {
                    "  <-- DEGRADED (raw, no label)"
                } else {
                    ""
                },
            ));
        }
    }
    (lines, n_fields, n_degraded)
}

fn render_review(
    entries: &[Emitted],
    skips: &[SkipReport],
    policy: &Policy,
    provenance: CatalogueProvenance,
    evidence: Option<&CatalogueEvidence>,
    root: &[u8; 32],
    known_call_count: usize,
    known_call_set_hash: &[u8; 32],
    known_call_set_bits: usize,
    source_root: &Path,
) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("# ERC-7730 descriptor catalogue\n");
    s.push_str("# Generated by `cargo run -p dbgen`. DO NOT EDIT BY HAND.\n");
    s.push_str("#\n");
    s.push_str("# Each row is one entry in the firmware-pinned Merkle tree at\n");
    s.push_str("# ERC7730_DESCRIPTORS_ROOT, followed by its emitted format intent and\n");
    s.push_str("# per-field op/label, canonical path bytes, raw parameter TLVs and\n");
    s.push_str("# device-decoded semantics — i.e. what actually RENDERS on-device,\n");
    s.push_str("# not what the JSON claims. A `degraded` count\n");
    s.push_str("# flags raw-op fields with no label: author-intended formatting\n");
    s.push_str("# that was silently lost. Auditors should reconcile every row\n");
    s.push_str("# against the source JSON and the upstream attestation chain.\n");
    s.push_str("# The trailing `## skips` section lists every descriptor or\n");
    s.push_str("# individual source format the tolerant build dropped (compile\n");
    s.push_str("# failure, safe-format cap, or dedup), by exact reason.\n");
    s.push_str(&format!("# Root: 0x{}\n", hex::encode(root)));
    s.push_str(&format!("# Provenance: {}\n", provenance.as_str()));
    s.push_str(&format!(
        "# Known contract calls: {known_call_count} ({}-byte omission filter; {known_call_set_bits}/{} bits set; hard cap 25%)\n",
        BLOOM_BYTES,
        BLOOM_BYTES * 8,
    ));
    s.push_str(&format!(
        "# Known-call tuple-set SHA-256: 0x{}\n",
        hex::encode(known_call_set_hash),
    ));
    s.push_str(&format!(
        "# Policy: min_attesters={} allow_unattested_dev_descriptors={}\n",
        policy.min_attesters, policy.allow_unattested_dev_descriptors
    ));
    s.push_str(&format!(
        "# Configured attesters ({}):\n",
        policy.trusted_attesters.len()
    ));
    for t in &policy.trusted_attesters {
        s.push_str(&format!("#   - {t}\n"));
    }
    if let Some(evidence) = evidence {
        let accepted_hashes: BTreeSet<[u8; 32]> =
            entries.iter().map(|entry| entry.erc8176_hash).collect();
        let accepted_attestations: usize = accepted_hashes
            .iter()
            .map(|hash| evidence.verified.attester_count(*hash))
            .sum();
        s.push_str(&format!(
            "# ERC-8176 draft revision: {ERC8176_DRAFT_COMMIT}\n"
        ));
        s.push_str(&format!(
            "# ERC-8176 policy SHA-256: 0x{}\n",
            hex::encode(evidence.policy_sha256)
        ));
        s.push_str(&format!(
            "# ERC-8176 snapshot SHA-256: 0x{}\n",
            hex::encode(evidence.verified.snapshot_sha256())
        ));
        s.push_str(&format!(
            "# ERC-8176 checkpoint: block={} hash=0x{} timestamp={}\n",
            evidence.verified.checkpoint_block_number(),
            hex::encode(evidence.verified.checkpoint_block_hash()),
            evidence.verified.checkpoint_timestamp(),
        ));
        s.push_str(&format!(
            "# ERC-8176 evaluation: timestamp={} max_checkpoint_age_seconds={} min_remaining_validity_seconds={}\n",
            evidence.verified.evaluation_timestamp(),
            evidence.verified.max_checkpoint_age_seconds(),
            evidence.verified.min_remaining_validity_seconds(),
        ));
        s.push_str(&format!(
            "# ERC-8176 verified snapshot: {} attestation record(s), {} descriptor hash(es); accepted catalogue: {} hash(es), {} leaf/leaves, {} distinct hash/attester authorization(s)\n",
            evidence.verified.attestation_count(),
            evidence.verified.descriptor_count(),
            accepted_hashes.len(),
            entries.len(),
            accepted_attestations,
        ));
    }
    if provenance == CatalogueProvenance::DevUnattested {
        s.push_str("#\n");
        s.push_str("# WARNING: dev mode is on — attestations were NOT enforced.\n");
        s.push_str("# CI MUST reject production builds in this mode.\n");
    }
    s.push('\n');

    let mut total_degraded = 0usize;
    for e in entries {
        let ctx = if e.context_kind == CTX_CONTRACT {
            "contract"
        } else {
            "eip712"
        };
        let (field_lines, n_fields, n_degraded) = review_field_breakdown(&e.ir_bytes);
        total_degraded += n_degraded;
        s.push_str(&format!(
            "[{:04}] ctx={ctx} chain_id={} contract=0x{} \
             primary_type=0x{} descriptor_hash=0x{} erc8176_hash=0x{} ir_len={} \
             fields={} degraded={} source={}\n",
            e.leaf_index,
            e.chain_id,
            hex::encode(e.contract),
            hex::encode(e.primary_type_hash),
            hex::encode(e.descriptor_hash),
            hex::encode(e.erc8176_hash),
            e.ir_bytes.len(),
            n_fields,
            n_degraded,
            e.source.file_name().unwrap().to_string_lossy(),
        ));
        for line in field_lines {
            s.push_str(&line);
            s.push('\n');
        }
    }

    // ── Skip roll-up ─────────────────────────────────────────────────
    // Committed + drift-gated, so a resync that drops descriptors to
    // blind-sign shows up as a reviewable diff with reasons (finding 1.4).
    s.push_str("\n## skips (");
    s.push_str(&skips.len().to_string());
    s.push_str(" total)\n");
    if total_degraded > 0 {
        s.push_str(&format!(
            "## WARNING: {total_degraded} DEGRADED field(s) across accepted leaves \
             (raw-op, no label — silently lost formatting; see finding 1.1)\n"
        ));
    }
    if !skips.is_empty() {
        // Category counts (sorted by category name for stable diffs).
        let mut by_cat: BTreeMap<&'static str, usize> = BTreeMap::new();
        for sk in skips {
            *by_cat.entry(review_skip_category(&sk.reason)).or_insert(0) += 1;
        }
        s.push_str("#\n# by category:\n");
        for (cat, n) in &by_cat {
            s.push_str(&format!("#   {n:>4}  {cat}\n"));
        }
        s.push('\n');
        // Per-skip detail, sorted by source path for stable diffs.
        let mut sorted: Vec<&SkipReport> = skips.iter().collect();
        sorted.sort_by(|a, b| a.source.cmp(&b.source));
        for sk in sorted {
            let source = review_relative_path(&sk.source, source_root);
            let reason = review_stable_reason(&sk.reason, source_root);
            s.push_str(&format!("{} — {}\n", source, reason.replace('\n', " "),));
        }
    }
    s
}

/// Stable path spelling for the committed review artifact.
///
/// `SkipReport::source` is absolute when dbgen is invoked from an absolute
/// workspace path. Emitting it directly makes `--check` depend on the checkout
/// directory and leaks a developer's home path. Prefer the catalogue-relative
/// path; an out-of-root source is reduced to its basename rather than exposing
/// an arbitrary host path.
fn review_relative_path(path: &Path, source_root: &Path) -> String {
    let stable = path
        .strip_prefix(source_root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .or_else(|| path.file_name().map(Path::new))
        .unwrap_or_else(|| Path::new("<unknown-source>"));
    stable.to_string_lossy().replace('\\', "/")
}

/// Remove the absolute catalogue-root prefix from diagnostics embedded in the
/// review file. The underlying build error retains its detailed path in stderr;
/// the committed receipt uses an explicit stable marker.
fn review_stable_reason(reason: &str, source_root: &Path) -> String {
    let root = source_root.to_string_lossy();
    if root.is_empty() {
        return reason.to_string();
    }
    reason.replace(root.as_ref(), "<catalog-root>")
}

// ─────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────

fn push_tlv(out: &mut Vec<u8>, kind: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_POOL_TLV_PAYLOAD {
        return Err(format!(
            "param TLV 0x{:02x}: payload too long ({} > {})",
            kind,
            payload.len(),
            MAX_POOL_TLV_PAYLOAD
        ));
    }
    out.push(kind);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    Ok(())
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() > 64 {
        return Err(format!("hex32 too long: {}", s.len()));
    }
    let padded = format!("{:0>64}", s);
    let bytes = hex::decode(&padded).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_address_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 20], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_address(hex);
    }
    parse_address(s)
}

/// Compile the ERC-7730 `nativeCurrencyAddress` scalar-or-list union into the
/// authenticated `PARAM_NATIVE_CURRENCY` payload.
///
/// A scalar remains exactly 20 bytes for backward compatibility. A list is
/// concatenated in descriptor order with no count byte: its validated payload
/// width is unambiguous. The pinned registry needs at most two members; larger
/// lists are deliberately refused instead of truncated.
fn compile_native_currency_addresses(
    value: &serde_json::Value,
    ctx: &CompileCtx,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    match value {
        serde_json::Value::String(address) => {
            out.extend_from_slice(&resolve_address_or_const(address, ctx)?);
        }
        serde_json::Value::Array(addresses) => {
            if addresses.is_empty() {
                return Err("tokenAmount.nativeCurrencyAddress list must not be empty".to_string());
            }
            if addresses.len() > pqsigner_erc7730::render::params::MAX_NATIVE_CURRENCY_ADDRESSES {
                return Err(format!(
                    "tokenAmount.nativeCurrencyAddress list has {} entries (max {})",
                    addresses.len(),
                    pqsigner_erc7730::render::params::MAX_NATIVE_CURRENCY_ADDRESSES
                ));
            }
            for (idx, entry) in addresses.iter().enumerate() {
                let address = entry.as_str().ok_or_else(|| {
                    format!("tokenAmount.nativeCurrencyAddress[{idx}] must be a string")
                })?;
                let resolved = resolve_address_or_const(address, ctx)?;
                if out
                    .chunks_exact(pqsigner_erc7730::render::params::NATIVE_CURRENCY_ADDRESS_LEN)
                    .any(|existing| existing == resolved.as_slice())
                {
                    return Err(format!(
                        "tokenAmount.nativeCurrencyAddress[{idx}] duplicates an earlier address"
                    ));
                }
                out.extend_from_slice(&resolved);
            }
        }
        _ => {
            return Err(
                "tokenAmount.nativeCurrencyAddress must be a string or string array".to_string(),
            )
        }
    }
    Ok(out)
}

fn resolve_u256_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 32], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_hex32(hex);
    }
    parse_hex32(s)
}

/// Resolve a constant-annotation field's `value`: either a literal string,
/// or a `$.metadata.constants.X` reference into the descriptor's metadata
/// constants (the ERC-4626 / ERC-7540 vault templates reference
/// `vaultTicker` / `underlyingTicker` this way).
fn resolve_string_or_const(s: &str, ctx: &CompileCtx) -> Result<String, String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        return v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("constant `{c}` is not a string"));
    }
    Ok(s.to_string())
}

/// Security-relevant strings must be represented byte-for-byte in the IR.
/// Transliteration/truncation is acceptable for cosmetic metadata, but not for
/// a unit or constant that changes the meaning of a signed value.
fn clean_ascii_exact(s: &str, max_len: usize, what: &str) -> Result<String, String> {
    if s.len() > max_len {
        return Err(format!("{what} is {} bytes; maximum is {max_len}", s.len()));
    }
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(format!("{what} must be printable ASCII"));
    }
    Ok(s.to_string())
}

/// Transliterate non-printable / non-ASCII bytes to '?', then trim to
/// `max_len` bytes. The on-device IR header forbids non-printable
/// bytes outright; the host pipeline replaces them rather than
/// rejecting wholesale, which mirrors the spec's "transliterate or
/// reject" guidance (see handoff §"Common gotchas" #3).
fn clean_ascii_truncated(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if out.len() >= max_len {
            break;
        }
        let mut buf = [0u8; 4];
        let enc = c.encode_utf8(&mut buf);
        if enc.len() == 1 && (0x20..0x7f).contains(&(enc.as_bytes()[0])) {
            out.push_str(enc);
        } else {
            out.push('?');
        }
    }
    out
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// Keep clippy happy about the `node_hash` import — we use it
// indirectly via `MerkleTree::build`.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = node_hash;
}

// ─────────────────────────────────────────────────────────────────────
// Tests.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_status_is_derived_from_exact_in_memory_build_outputs() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let input = root.join("secure/data/erc7730");
        let result = build_db(&input, &input.join("policy.toml")).unwrap();
        let curation = [0x88; 32];

        let status = catalogue_status_v1(&result, curation).unwrap();
        assert_eq!(status.catalogue_format_version, ERC7730_DB_VERSION);
        assert_eq!(status.ir_schema_version, SCHEMA_VER);
        assert_eq!(status.leaf_count as usize, result.leaf_count);
        assert_eq!(status.catalogue_blob_size as usize, result.blob.len());
        assert_eq!(status.known_call_count as usize, result.known_call_count);
        assert_eq!(status.bloom_size as usize, BLOOM_BYTES);
        assert_eq!(status.descriptor_root, result.root);
        assert_eq!(status.catalogue_sha256, sha256_of(&result.blob));
        assert_eq!(status.known_call_set_sha256, result.known_call_set_hash);
        assert_eq!(status.bloom_sha256, sha256_of(&result.known_calls_bloom));
        assert_eq!(status.policy_sha256, result.policy_sha256);
        assert_eq!(status.curation_input_sha256, curation);
        assert_eq!(status.tool_version(), b"dbgen/0.1.0");
        assert_eq!(
            pqsigner_erc7730::catalogue_status::CatalogueStatusV1::from_bytes(&status.to_bytes())
                .unwrap(),
            status
        );
    }

    #[test]
    fn forced_eligible_encoder_is_canonical_big_endian() {
        let first_target = [0x11; 20];
        let second_target = [0x22; 20];
        let calls = [
            (1, first_target, [0x01, 0x02, 0x03, 0x04]),
            (1, first_target, [0x05, 0x06, 0x07, 0x08]),
            (0x0102_0304_0506_0708, second_target, [0xaa; 4]),
        ];
        let encoded = encode_forced_eligible_set(&calls).unwrap();
        assert_eq!(&encoded[..4], b"P73K");
        assert_eq!(&encoded[4..6], &1u16.to_be_bytes());
        assert_eq!(&encoded[6..8], &16u16.to_be_bytes());
        assert_eq!(&encoded[8..12], &2u32.to_be_bytes());
        assert_eq!(&encoded[12..16], &3u32.to_be_bytes());
        assert_eq!(&encoded[16..24], &1u64.to_be_bytes());
        assert_eq!(&encoded[24..44], &first_target);
        assert_eq!(&encoded[44..48], &0u32.to_be_bytes());
        assert_eq!(&encoded[48..50], &2u16.to_be_bytes());
        assert_eq!(&encoded[50..52], &[0, 0]);
        assert_eq!(&encoded[52..60], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&encoded[60..80], &second_target);
        assert_eq!(&encoded[80..84], &2u32.to_be_bytes());
        assert_eq!(&encoded[84..86], &1u16.to_be_bytes());
        assert_eq!(&encoded[86..88], &[0, 0]);
        assert_eq!(
            &encoded[88..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xaa, 0xaa, 0xaa, 0xaa,]
        );
        assert_eq!(
            ForcedEligibleSet::from_bytes(&encoded)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            calls
        );
        assert!(encode_forced_eligible_set(&[calls[1], calls[0]]).is_err());
        assert_eq!(
            encode_forced_eligible_set(&[]).unwrap(),
            [b'P', b'7', b'3', b'K', 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn p730_recovery_rejects_contract_ir_without_a_selector_format() {
        let chain_id = 1u64;
        let contract = [0x44; 20];
        let mut ir = vec![0u8; HEADER_LEN];
        ir[0] = SCHEMA_VER;
        ir[1] = CTX_CONTRACT;
        ir[2..10].copy_from_slice(&chain_id.to_be_bytes());
        ir[10..30].copy_from_slice(&contract);
        ir[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        ir[128..130].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        assert!(
            Erc7730Ir::parse(&ir).is_ok(),
            "IR parser permits empty formats"
        );

        let pool_off = ERC7730_DB_HEADER_LEN + ERC7730_DB_ENTRY_LEN;
        let proofs_off = pool_off + ir.len();
        let mut blob = Vec::new();
        blob.extend_from_slice(&ERC7730_DB_MAGIC);
        write_u32_le(&mut blob, ERC7730_DB_VERSION);
        write_u32_le(&mut blob, 0);
        write_u32_le(&mut blob, 1);
        write_u32_le(&mut blob, pool_off as u32);
        write_u32_le(&mut blob, ir.len() as u32);
        write_u32_le(&mut blob, 0);
        write_u32_le(&mut blob, proofs_off as u32);
        blob.extend_from_slice(&chain_id.to_le_bytes());
        blob.extend_from_slice(&contract);
        blob.extend_from_slice(&[0u8; 32]);
        blob.push(CTX_CONTRACT);
        blob.extend_from_slice(&[0u8; 3]);
        write_u32_le(&mut blob, 0);
        write_u32_le(&mut blob, ir.len() as u32);
        blob.extend_from_slice(&ir);
        assert_eq!(blob.len(), proofs_off);

        let error = recover_clear_contract_calls_from_p730(&blob).unwrap_err();
        assert!(error.contains("no selector-bearing formats"), "{error}");
    }

    #[test]
    fn erc8176_policy_attester_identities_are_exact_and_unique() {
        let first = "eip155:1:0x1111111111111111111111111111111111111111".to_string();
        let second = "eip155:1:0x2222222222222222222222222222222222222222".to_string();
        let parsed = parse_trusted_attesters(&[first.clone(), second]).unwrap();
        assert_eq!(parsed.len(), 2);

        for bad in [
            Vec::<String>::new(),
            vec![first.clone(), first.clone()],
            vec!["eip155:1:0x0000000000000000000000000000000000000000".to_string()],
            vec!["eip155:10:0x1111111111111111111111111111111111111111".to_string()],
            vec!["eip155:1:0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
            vec!["eip155:1:1111111111111111111111111111111111111111".to_string()],
        ] {
            assert!(parse_trusted_attesters(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn erc8176_policy_and_snapshot_paths_are_bounded_and_non_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let policy_path = temp.path().join("policy.toml");
        let snapshot_path = temp.path().join("snapshot.json");
        fs::write(&policy_path, "allow_unattested_dev_descriptors = true\n").unwrap();
        fs::write(&snapshot_path, b"{}").unwrap();

        assert_eq!(
            resolve_policy_relative_snapshot(&policy_path, Path::new("snapshot.json")).unwrap(),
            snapshot_path.canonicalize().unwrap()
        );
        for bad in ["", ".", "./snapshot.json", "../snapshot.json"] {
            assert!(
                resolve_policy_relative_snapshot(&policy_path, Path::new(bad)).is_err(),
                "accepted snapshot path {bad:?}"
            );
        }
        assert!(resolve_policy_relative_snapshot(&policy_path, &snapshot_path).is_err());

        fs::write(
            temp.path().join("unknown.toml"),
            "unknown_authority = true\n",
        )
        .unwrap();
        assert!(load_policy(&temp.path().join("unknown.toml")).is_err());

        let ambiguous_path = temp.path().join("ambiguous.toml");
        fs::write(
            &ambiguous_path,
            concat!(
                "min_attesters = 2\n",
                "trusted_attesters = [\n",
                "  \"eip155:1:0x1111111111111111111111111111111111111111\",\n",
                "  \"eip155:1:0x2222222222222222222222222222222222222222\",\n",
                "]\n",
                "allow_unattested_dev_descriptors = true\n",
                "[erc8176_snapshot]\n",
                "path = \"snapshot.json\"\n",
                "sha256 = \"0x0000000000000000000000000000000000000000000000000000000000000000\"\n",
                "block_hash = \"0x0000000000000000000000000000000000000000000000000000000000000000\"\n",
                "block_number = 1\n",
                "block_timestamp = 1\n",
                "evaluation_time = 1\n",
                "max_checkpoint_age_secs = 1\n",
                "min_remaining_validity_secs = 1\n",
            ),
        )
        .unwrap();
        let error = load_policy_and_evidence(&ambiguous_path, true)
            .err()
            .expect("a dev policy cannot carry production evidence behind an override");
        assert!(
            error.contains("use a distinct production policy"),
            "{error}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let snapshot_link = temp.path().join("snapshot-link.json");
            symlink(&snapshot_path, &snapshot_link).unwrap();
            assert!(resolve_policy_relative_snapshot(
                &policy_path,
                Path::new("snapshot-link.json")
            )
            .is_err());

            let policy_link = temp.path().join("policy-link.toml");
            symlink(&policy_path, &policy_link).unwrap();
            assert!(read_policy_bytes(&policy_link).is_err());
        }
    }

    #[test]
    fn descriptor_source_snapshot_is_bounded_and_immutable_for_the_build() {
        let temp = tempfile::tempdir().unwrap();
        let descriptor = temp.path().join("calldata-race.json");
        fs::write(&descriptor, br#"{"version":1}"#).unwrap();

        let mut snapshot = DescriptorSourceSnapshot::default();
        let first = snapshot.load_json(&descriptor).unwrap();
        fs::write(&descriptor, br#"{"version":2}"#).unwrap();
        let second = snapshot.load_json(&descriptor).unwrap();
        assert_eq!(first, second, "later consumers must see the first read");
        assert_eq!(second["version"].as_u64(), Some(1));
        assert_eq!(snapshot.json_by_path.len(), 1);

        let oversized = temp.path().join("calldata-oversized.json");
        fs::write(
            &oversized,
            vec![b' '; MAX_DESCRIPTOR_SOURCE_BYTES as usize + 1],
        )
        .unwrap();
        let error = snapshot
            .load_json(&oversized)
            .expect_err("oversized descriptor source must fail before parsing");
        assert!(error.contains("per-file cap"), "{error}");
    }

    #[test]
    fn nested_calldata_authority_is_split_by_explicit_catalogue_route() {
        assert!(PRODUCTION_NESTED_CALLDATA_ENROLLMENTS.is_empty());
        #[cfg(feature = "nested-calldata-test-fixture")]
        assert_eq!(
            e2e_nested_calldata_enrollments(),
            pqsigner_erc7730::render::calldata_policy::TEST_NESTED_CALLDATA_ENROLLMENTS
        );
        #[cfg(not(feature = "nested-calldata-test-fixture"))]
        assert!(e2e_nested_calldata_enrollments().is_empty());
    }

    #[test]
    fn review_source_stamp_is_exact_and_single_use() {
        let source = RegistryReviewSource {
            upstream_commit: "11".repeat(20),
            upstream_tree: "22".repeat(20),
            manifest_sha256: [0x33; 32],
        };
        let mut review =
            format!("# ERC-7730 descriptor catalogue\n{REVIEW_GENERATOR_HEADER}#\n# Root: 0x00\n");
        stamp_registry_review_source(&mut review, &source).expect("stamp fresh review");
        assert_eq!(
            review,
            format!(
                concat!(
                    "# ERC-7730 descriptor catalogue\n",
                    "# Generated by `cargo run -p dbgen`. DO NOT EDIT BY HAND.\n",
                    "# Upstream registry commit: {}\n",
                    "# Upstream registry tree: {}\n",
                    "# Curation manifest SHA-256: {}\n",
                    "#\n",
                    "# Root: 0x00\n"
                ),
                "11".repeat(20),
                "22".repeat(20),
                "33".repeat(32),
            )
        );
        assert!(stamp_registry_review_source(&mut review, &source)
            .expect_err("duplicate stamp must fail")
            .contains("already carries"));
    }

    #[test]
    fn review_source_stamp_rejects_noncanonical_git_ids() {
        for bad in ["11".repeat(19), "AA".repeat(20), "gg".repeat(20)] {
            assert!(validate_git_object_id(&bad, "commit").is_err(), "{bad}");
        }
        validate_git_object_id(&"ab".repeat(20), "commit").expect("canonical object id");
    }

    #[test]
    fn selector_parser_canonicalizes_aliases_nested_arrays_whitespace_and_dollars() {
        assert_eq!(
            contract_selector_signature(
                "  $batch ( ( uint amount , byte tag ) [ ] calls, fixed rate, ufixed quote, address payable recipient )  "
            )
            .unwrap(),
            "$batch((uint256,bytes1)[],fixed128x18,ufixed128x18,address)"
        );
        assert_eq!(
            contract_selector_signature("foo$bar(int value, uint[2] values)").unwrap(),
            "foo$bar(int256,uint256[2])"
        );
        // Renderer name policy may reject duplicates/unnamed parameters, but
        // both still have an unambiguous selector and must enter the omission
        // set.
        assert_eq!(
            contract_selector_signature("f(address same,uint same)").unwrap(),
            "f(address,uint256)"
        );
        assert_eq!(
            contract_selector_signature("g((address,uint)[])").unwrap(),
            "g((address,uint256)[])"
        );
    }

    #[test]
    fn selector_parser_fails_closed_when_canonical_types_are_unknown() {
        for bad in [
            "0x12345678",
            "f(MyStruct value)",
            "f(uint7 value)",
            "f(uint256[00] value)",
            "f((address value] tuple)",
            "f(address value) trailing",
        ] {
            assert!(
                contract_selector_signature(bad).is_err(),
                "must not guess canonical selector for {bad}"
            );
        }
    }

    #[test]
    fn known_call_scanner_propagates_selector_derivation_failure() {
        let json = serde_json::json!({
            "context": {"contract": {"deployments": [{
                "chainId": 1,
                "address": "0x00000000000000000000000000000000000000d0"
            }]}},
            "display": {"formats": {
                "f(MyStruct value)": {"intent": "Call", "fields": []}
            }}
        });
        let err = collect_contract_calls_from_json(
            &json,
            &mut BTreeSet::new(),
            &mut DeclaredContractSignatures::new(),
        )
        .expect_err("an unknown canonical type must abort omission scanning");
        assert!(
            err.contains("unsupported ABI type `MyStruct`"),
            "got: {err}"
        );
    }

    #[test]
    fn known_call_scanner_hashes_dollar_name_and_alias_canonically() {
        let json = serde_json::json!({
            "context": {"contract": {"deployments": [{
                "chainId": 1,
                "address": "0x00000000000000000000000000000000000000d0"
            }]}},
            "display": {"formats": {
                "$foo(uint amount)": {"intent": "Call", "fields": []}
            }}
        });
        let mut declared = BTreeSet::new();
        let mut signatures = DeclaredContractSignatures::new();
        collect_contract_calls_from_json(&json, &mut declared, &mut signatures).unwrap();
        assert_eq!(declared.len(), 1);
        let key @ (_, _, selector) = declared.iter().next().unwrap();
        let digest = keccak256(b"$foo(uint256)");
        assert_eq!(*selector, [digest[0], digest[1], digest[2], digest[3]]);
        assert_eq!(
            signatures.get(key),
            Some(&BTreeSet::from(["$foo(uint256)".to_string()]))
        );
    }

    #[test]
    fn known_call_bloom_occupancy_gate_prevents_liveness_saturation() {
        let empty = [0u8; BLOOM_BYTES];
        assert_eq!(enforce_known_call_bloom_occupancy(&empty).unwrap(), 0);

        let saturated = [0xffu8; BLOOM_BYTES];
        let err = enforce_known_call_bloom_occupancy(&saturated)
            .expect_err("a saturated omission filter must fail generation");
        assert!(err.contains("cap 32768"), "got: {err}");
        assert!(err.contains("below 1/10000"), "got: {err}");
    }

    #[test]
    fn review_paths_and_reasons_are_checkout_independent() {
        let relative = Path::new("registry/project/calldata-token.json");
        let root_a = Path::new("/home/alice/PQSigner_OS/secure/data/erc7730-registry");
        let root_b = Path::new("/tmp/clean/PQSigner_OS/secure/data/erc7730-registry");
        let source_a = root_a.join(relative);
        let source_b = root_b.join(relative);

        assert_eq!(
            review_relative_path(&source_a, root_a),
            review_relative_path(&source_b, root_b)
        );
        assert_eq!(
            review_relative_path(&source_a, root_a),
            "registry/project/calldata-token.json"
        );

        let reason_a = format!("duplicate of {}", source_a.display());
        let reason_b = format!("duplicate of {}", source_b.display());
        assert_eq!(
            review_stable_reason(&reason_a, root_a),
            review_stable_reason(&reason_b, root_b)
        );
        assert_eq!(
            review_stable_reason(&reason_a, root_a),
            "duplicate of <catalog-root>/registry/project/calldata-token.json"
        );
    }

    #[test]
    fn known_call_set_receipt_is_order_independent_and_tuple_sensitive() {
        let tuple_a = (1u64, [0x11; 20], [0xa9, 0x05, 0x9c, 0xbb]);
        let tuple_b = (11_155_111u64, [0x22; 20], [0xd0, 0xe3, 0x0d, 0xb0]);

        let mut forward = BTreeSet::new();
        forward.insert(tuple_a);
        forward.insert(tuple_b);
        let mut reverse = BTreeSet::new();
        reverse.insert(tuple_b);
        reverse.insert(tuple_a);
        assert_eq!(
            known_call_set_hash(&forward).unwrap(),
            known_call_set_hash(&reverse).unwrap(),
            "filesystem/traversal order must not affect the receipt"
        );
        assert_eq!(
            hex::encode(known_call_set_hash(&forward).unwrap()),
            "7a4f9ae17e1ef3abf20abec54ec2df431170c3778495d8edda19aea63a80084e",
            "freeze domain tag, count width/endianness, and tuple encoding"
        );

        for changed in [
            (2u64, tuple_a.1, tuple_a.2),
            (tuple_a.0, [0x12; 20], tuple_a.2),
            (tuple_a.0, tuple_a.1, [0x09, 0x05, 0x9c, 0xbb]),
        ] {
            let mut variant = forward.clone();
            variant.remove(&tuple_a);
            variant.insert(changed);
            assert_ne!(
                known_call_set_hash(&forward).unwrap(),
                known_call_set_hash(&variant).unwrap(),
                "chain, contract, and selector are all security-significant"
            );
        }
    }

    #[test]
    fn strip_param_names_basic() {
        assert_eq!(
            strip_param_names("(address _to, uint256 _value)"),
            "(address,uint256)"
        );
    }

    // The v2 array gate hinges on `path_matches_member` correctly resolving the
    // `.[]` whole-array wildcard (advisor review target): a per-element field
    // `M.[].addr` must COVER the element address `M.[].addr` (else PermitBatch/
    // Rarible false-refuse), while an INDEXED/sliced segment must NOT match (it
    // names one element the gate can't reason about → a hidden-address risk).
    #[test]
    fn path_matches_member_array_wildcard() {
        // v2 whole-array wildcard: a per-element field covers the element member.
        assert!(path_matches_member("details.[].token", "details.[].token"));
        assert!(path_matches_member(
            "creators.[].account",
            "creators.[].account"
        ));
        // Different member under the same array → NOT covered.
        assert!(!path_matches_member(
            "details.[].amount",
            "details.[].token"
        ));
        // A non-array field must NOT cover an array member, and vice-versa.
        assert!(!path_matches_member("details.token", "details.[].token"));
        assert!(!path_matches_member("details.[].token", "details.token"));
        // INDEXED / sliced segments name a specific element → rejected (the
        // security-critical case: they must never satisfy per-element coverage).
        assert!(!path_matches_member(
            "details.[0].token",
            "details.[].token"
        ));
        assert!(!path_matches_member(
            "details.[-1].token",
            "details.[].token"
        ));
        assert!(!path_matches_member(
            "details.[0:20].token",
            "details.[].token"
        ));
        // v1 (non-array) matching is unchanged.
        assert!(path_matches_member("details.token", "details.token"));
        assert!(!path_matches_member("details.token", "details.amount"));
        assert!(path_matches_member("#.details.token", "details.token"));
        assert!(!path_matches_member("@.to", "details.token"));
    }

    #[test]
    fn terminal_type_walks_whole_array_struct_members_but_not_indexed_descents() {
        let sig = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();

        assert_eq!(
            rendered_path_terminal_type("details.[].amount", CTX_EIP712, &parsed).unwrap(),
            Some("uint160".to_string())
        );
        assert_eq!(
            terminal_kind_for_path("details.[].amount", CTX_EIP712, &parsed).unwrap(),
            TerminalKind::Unsigned
        );
        assert_eq!(
            terminal_kind_for_path("details.[].token", CTX_EIP712, &parsed).unwrap(),
            TerminalKind::Address
        );

        for hostile in [
            "details.[0].amount",
            "details.[-1].amount",
            "details.[0:1].amount",
        ] {
            assert!(
                rendered_path_terminal_type(hostile, CTX_EIP712, &parsed).is_err(),
                "an indexed/sliced descent must not inherit whole-array coverage: {hostile}"
            );
        }
    }

    #[test]
    fn strip_abs_prefix_relative_remainder() {
        // Returns the FULL remaining path relative to the element `prefix`
        // (the recursion strips one prefix level per depth). v1/v2/v3 shapes:
        assert_eq!(
            strip_abs_prefix("details.amount", "details"),
            Some("amount")
        );
        assert_eq!(
            strip_abs_prefix("details.[].amount", "details.[]"),
            Some("amount")
        );
        assert_eq!(
            strip_abs_prefix("witness.info.reactor", "witness"),
            Some("info.reactor")
        );
        assert_eq!(
            strip_abs_prefix("witness.outputs.[].endAmount", "witness.outputs.[]"),
            Some("endAmount")
        );
        // A bare element reference (whole-struct) or a non-match → None.
        assert_eq!(strip_abs_prefix("witness", "witness"), None);
        assert_eq!(strip_abs_prefix("other.amount", "details"), None);
        // Array-ness must match the prefix: a `[]` element path under a
        // non-array prefix leaves the bracket in the remainder (still stripped
        // one level per recursion, so this is the parent's view).
        assert_eq!(
            strip_abs_prefix("details.[].amount", "details"),
            Some("[].amount")
        );
    }

    #[test]
    fn eip712_member_is_static_scalar_gate() {
        // Static single-word scalars → true.
        for t in [
            "address", "bool", "uint256", "uint160", "uint48", "int128", "bytes32", "bytes1",
        ] {
            assert!(
                eip712_member_is_static_scalar(t),
                "{t} must be a static scalar"
            );
        }
        // Dynamic / composite → false (would mis-render keccak(value)/hashStruct).
        for t in [
            "bytes",
            "string",
            "uint256[]",
            "address[]",
            "DutchOutput",
            "bytes33",
            "uint7",
            "uint",
        ] {
            assert!(
                !eip712_member_is_static_scalar(t),
                "{t} must NOT be a static scalar"
            );
        }
    }

    fn compile_eip712_test_format(sig: &str, fields_json: &str) -> Result<Vec<u8>, String> {
        let fmt = fmt_from_fields(fields_json);
        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )?;
        Ok(out)
    }

    #[test]
    fn visible_flat_eip712_hash_words_are_rejected() {
        let cases = [
            (
                "Message(string text,uint256 effect)",
                r#"[
                    {"path":"text","label":"Text","format":"raw"},
                    {"path":"effect","label":"Effect","format":"raw"}
                ]"#,
                "string",
            ),
            (
                "Message(bytes payload,uint256 effect)",
                r#"[
                    {"path":"payload","label":"Payload","format":"raw"},
                    {"path":"effect","label":"Effect","format":"raw"}
                ]"#,
                "bytes",
            ),
            (
                "Batch(uint256[] values,uint256 effect)",
                r#"[
                    {"path":"values","label":"Values","format":"raw"},
                    {"path":"effect","label":"Effect","format":"raw"}
                ]"#,
                "uint256[]",
            ),
            (
                "Envelope(Meta meta,uint256 effect)Meta(uint256 value)",
                r#"[
                    {"path":"meta","label":"Meta","format":"raw"},
                    {"path":"effect","label":"Effect","format":"raw"}
                ]"#,
                "Meta",
            ),
        ];

        for (sig, fields, terminal_type) in cases {
            let err = compile_eip712_test_format(sig, fields)
                .expect_err("visible hash-only typed-data member must be refused");
            assert!(
                err.contains("visible EIP-712 terminal type")
                    && err.contains(terminal_type)
                    && err.contains("opaque hash word"),
                "unexpected refusal for {sig}: {err}"
            );
        }
    }

    const SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH: [u8; 32] = [0x42; 32];
    const SYNTHETIC_EIP712_STRING_CONTRACT: [u8; 20] = [0x24; 20];
    const SYNTHETIC_EIP712_STRING_SIGNATURE: &str = "Message(string contents)";
    const SYNTHETIC_EIP712_STRING_FIELDS: [Eip712StringPreimageFieldEnrollment; 1] =
        [Eip712StringPreimageFieldEnrollment {
            path: "contents",
            ordinal: 0,
        }];

    fn synthetic_eip712_string_enrollment() -> Eip712StringPreimageEnrollment {
        Eip712StringPreimageEnrollment {
            descriptor_hash: SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            chain_id: 31_337,
            contract: SYNTHETIC_EIP712_STRING_CONTRACT,
            canonical_signature: SYNTHETIC_EIP712_STRING_SIGNATURE,
            type_hash: keccak256(SYNTHETIC_EIP712_STRING_SIGNATURE.as_bytes()),
            fields: &SYNTHETIC_EIP712_STRING_FIELDS,
        }
    }

    fn synthetic_eip712_string_deployment(
        capabilities: &Erc20Capabilities,
    ) -> InterpolationDeployment<'_> {
        InterpolationDeployment {
            chain_id: 31_337,
            contract: SYNTHETIC_EIP712_STRING_CONTRACT,
            erc20_capabilities: capabilities,
        }
    }

    #[test]
    fn synthetic_eip712_string_preimage_emits_exact_static_word_marker() {
        let sig = SYNTHETIC_EIP712_STRING_SIGNATURE;
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
                {"path":"contents","label":"Contents","format":"raw","visible":"always"}
            ]"#,
        );
        let capabilities = Erc20Capabilities::default();
        let deployment = synthetic_eip712_string_deployment(&capabilities);
        let enrollments = [synthetic_eip712_string_enrollment()];
        let enrollment = eip712_string_preimage_enrollment_for_in(
            &enrollments,
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&deployment),
            sig,
            keccak256(sig.as_bytes()),
        )
        .expect("synthetic exact descriptor/deployment/encodeType enrollment");
        assert_eq!(
            validate_eip712_string_preimage_format_source(sig, &fmt, &parsed, enrollment),
            Ok(1)
        );

        let mut pool = Pool::new();
        let compiled = compile_one_field_with_profile(
            sig,
            0,
            &fmt.fields[0],
            CTX_EIP712,
            &parsed,
            &mut test_ctx(),
            &mut pool,
            &BTreeMap::new(),
            false,
            false,
            false,
            Some(0),
            false,
        )
        .expect("enrolled direct string field compiles");
        assert_eq!(compiled.format_op, FMT_RAW);
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_EIP712_STRING_PREIMAGE),
            Some(&[0][..])
        );
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_TERMINAL_KIND),
            Some(&[TerminalKind::Eip712StringHashWord as u8][..])
        );
        let pool_bytes = pool.into_bytes();
        let path_len = pool_bytes[compiled.path_off as usize] as usize;
        assert_eq!(
            &pool_bytes[compiled.path_off as usize + 1..compiled.path_off as usize + 1 + path_len],
            [PATHOP_ROOT_STRUCT, PATHOP_FIELD_IDX, 0, 0],
            "EIP-712 string paths name the signed hash word directly; they never FollowOffset"
        );
    }

    #[test]
    fn synthetic_eip712_string_enrollment_identity_and_source_drift_fail_closed() {
        let capabilities = Erc20Capabilities::default();
        let exact = synthetic_eip712_string_deployment(&capabilities);
        let enrollments = [synthetic_eip712_string_enrollment()];
        let exact_type_hash = keccak256(SYNTHETIC_EIP712_STRING_SIGNATURE.as_bytes());
        assert!(eip712_string_preimage_enrollment_for_in(
            &enrollments,
            [0x55; 32],
            Some(&exact),
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            exact_type_hash,
        )
        .is_none());
        assert!(eip712_string_preimage_enrollment_for_in(
            &enrollments,
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&InterpolationDeployment {
                chain_id: exact.chain_id + 1,
                ..exact
            }),
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            exact_type_hash,
        )
        .is_none());
        assert!(eip712_string_preimage_enrollment_for_in(
            &enrollments,
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&exact),
            "Message(string other)",
            exact_type_hash,
        )
        .is_none());
        let mut wrong_type_hash = exact_type_hash;
        wrong_type_hash[31] ^= 1;
        assert!(eip712_string_preimage_enrollment_for_in(
            &enrollments,
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&exact),
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            wrong_type_hash,
        )
        .is_none());

        let enrollment = eip712_string_preimage_enrollment_for_in(
            &enrollments,
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&exact),
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            exact_type_hash,
        )
        .unwrap();
        let parsed = parse_format_key(SYNTHETIC_EIP712_STRING_SIGNATURE).unwrap();
        for (field_json, needle) in [
            (
                r#"[{"path":"contents","label":"Contents","format":"amount","visible":"always"}]"#,
                "explicitly use raw",
            ),
            (
                r#"[{"path":"contents","label":"Contents","format":"raw","visible":"optional"}]"#,
                "visible always",
            ),
            (
                r#"[
                    {"path":"contents","label":"Contents","format":"raw","visible":"always"},
                    {"path":"contents","label":"Duplicate","format":"raw","visible":"always"}
                ]"#,
                "field set/order drift",
            ),
        ] {
            let fmt = fmt_from_fields(field_json);
            let error = validate_eip712_string_preimage_format_source(
                SYNTHETIC_EIP712_STRING_SIGNATURE,
                &fmt,
                &parsed,
                enrollment,
            )
            .expect_err("source drift must revoke preimage authority");
            assert!(error.contains(needle), "unexpected refusal: {error}");
        }

        const MULTI_STRING_SIGNATURE: &str =
            "Envelope(address recipient,string title,string body,uint256 nonce)";
        const MULTI_STRING_FIELDS: [Eip712StringPreimageFieldEnrollment; 2] = [
            Eip712StringPreimageFieldEnrollment {
                path: "title",
                ordinal: 0,
            },
            Eip712StringPreimageFieldEnrollment {
                path: "body",
                ordinal: 1,
            },
        ];
        let multi_enrollment = Eip712StringPreimageEnrollment {
            canonical_signature: MULTI_STRING_SIGNATURE,
            type_hash: keccak256(MULTI_STRING_SIGNATURE.as_bytes()),
            fields: &MULTI_STRING_FIELDS,
            ..*enrollment
        };
        let multi_parsed = parse_format_key(MULTI_STRING_SIGNATURE).unwrap();
        let mut reordered = fmt_from_fields(
            r#"[
                {"path":"recipient","label":"Recipient","format":"addressName","visible":"always"},
                {"path":"title","label":"Title","format":"raw","visible":"always"},
                {"path":"body","label":"Body","format":"raw","visible":"always"},
                {"path":"nonce","label":"Nonce","format":"raw","visible":"always"}
            ]"#,
        );
        reordered.fields.swap(1, 2);
        assert!(validate_eip712_string_preimage_format_source(
            MULTI_STRING_SIGNATURE,
            &reordered,
            &multi_parsed,
            &multi_enrollment,
        )
        .expect_err("string evidence traversal reorder must be refused")
        .contains("field set/order drift"));

        const BAD_FIELDS: [Eip712StringPreimageFieldEnrollment; 1] =
            [Eip712StringPreimageFieldEnrollment {
                path: "contents",
                ordinal: 1,
            }];
        let bad_ordinal_enrollment = Eip712StringPreimageEnrollment {
            fields: &BAD_FIELDS,
            ..*enrollment
        };
        assert!(validate_eip712_string_preimage_format_source(
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            &fmt_from_fields(
                r#"[{"path":"contents","label":"Contents","format":"raw","visible":"always"}]"#
            ),
            &parsed,
            &bad_ordinal_enrollment,
        )
        .expect_err("non-canonical marker ordinal must be refused")
        .contains("ordinals must be canonical"));

        const NESTED_FIELDS: [Eip712StringPreimageFieldEnrollment; 1] =
            [Eip712StringPreimageFieldEnrollment {
                path: "meta.contents",
                ordinal: 0,
            }];
        let nested_sig = "Envelope(Meta meta)Meta(string contents)";
        let nested_enrollment = Eip712StringPreimageEnrollment {
            canonical_signature: nested_sig,
            type_hash: keccak256(nested_sig.as_bytes()),
            fields: &NESTED_FIELDS,
            ..*enrollment
        };
        assert!(validate_eip712_string_preimage_format_source(
            nested_sig,
            &fmt_from_fields(
                r#"[{"path":"meta.contents","label":"Contents","format":"raw","visible":"always"}]"#
            ),
            &parse_format_key(nested_sig).unwrap(),
            &nested_enrollment,
        )
        .expect_err("nested child strings are outside the enrolled topology")
        .contains("not a direct top-level member"));
    }

    #[test]
    fn neighbouring_unenrolled_eip712_strings_remain_opaque() {
        let mut ctx = test_ctx();
        ctx.descriptor_hash = SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH;
        let capabilities = Erc20Capabilities::default();
        let deployment = synthetic_eip712_string_deployment(&capabilities);
        let error = {
            let fmt = fmt_from_fields(
                r#"[
                    {"path":"contents","label":"Contents","format":"raw"},
                    {"path":"nonce","label":"Nonce","format":"raw"}
                ]"#,
            );
            let mut pool = Pool::new();
            let mut out = Vec::new();
            compile_one_format(
                "Update(string contents,uint256 nonce)",
                &fmt,
                CTX_EIP712,
                &mut ctx,
                &mut pool,
                &BTreeMap::new(),
                &mut out,
                Some(&deployment),
            )
            .expect_err("same descriptor/deployment does not enroll neighbouring strings")
        };
        assert!(
            error.contains("opaque hash word"),
            "unenrolled synthetic string must preserve the refusal: {error}"
        );
    }

    #[test]
    fn hidden_dynamic_eip712_members_are_rejected() {
        let err = compile_eip712_test_format(
            "Message(uint256 amount,string memo,bytes payload,uint256[] values)",
            r#"[
                {"path":"amount","label":"Amount","format":"raw"},
                {"path":"memo","label":"Memo","format":"raw","visible":"never"},
                {"path":"payload","label":"Payload","format":"raw","visible":"never"},
                {"path":"values","label":"Values","format":"raw","visible":"never"}
            ]"#,
        )
        .expect_err("hidden dynamic/hash-only members remain signed semantics");
        assert!(
            err.contains("terminal type `string`") && err.contains("visible:\"never\""),
            "typed hidden-field refusal: {err}"
        );
    }

    #[test]
    fn hyperliquid_withdraw_string_values_are_rejected() {
        let err = compile_eip712_test_format(
            "HyperliquidTransaction:Withdraw(string hyperliquidChain,string destination,string amount,uint64 time)",
            r#"[
                {"path":"destination","label":"Recipient","format":"raw"},
                {"path":"amount","label":"USDC amount","format":"raw"},
                {"path":"hyperliquidChain","label":"Chain","format":"raw"},
                {"path":"time","label":"Time","format":"raw"}
            ]"#,
        )
        .expect_err("Hyperliquid strings would render their keccak words, not destination/amount/chain");
        assert!(
            err.contains("visible EIP-712 terminal type `string`")
                && err.contains("opaque hash word"),
            "unexpected Hyperliquid refusal: {err}"
        );
    }

    #[test]
    fn nested_anchor_with_hidden_dynamic_child_is_rejected() {
        let err = compile_eip712_test_format(
            "Envelope(Meta meta,uint256 nonce)Meta(string memo,uint256 amount)",
            r#"[
                {"path":"meta.memo","label":"Memo","format":"raw","visible":"never"},
                {"path":"meta.amount","label":"Amount","format":"raw"},
                {"path":"nonce","label":"Nonce","format":"raw"}
            ]"#,
        )
        .expect_err("authenticated nesting does not make an unseen payload WYSIWYS-safe");
        assert!(
            err.contains("terminal type `string`") && err.contains("visible:\"never\""),
            "typed hidden-field refusal: {err}"
        );
    }

    #[test]
    fn explicit_eip712_domain_separator_is_rejected() {
        let ctx: Context = serde_json::from_value(serde_json::json!({
            "eip712": {
                "deployments": [{
                    "chainId": 1,
                    "address": "0x1111111111111111111111111111111111111111"
                }],
                "domainSeparator": format!("0x{}", "22".repeat(32))
            }
        }))
        .unwrap();
        let err = reject_unsupported_context_semantics(&ctx)
            .expect_err("an arbitrary explicit separator must never be trusted");
        assert!(
            err.contains("context.eip712.domainSeparator")
                && err.contains("chainId/verifyingContract"),
            "unexpected rejection: {err}"
        );
    }

    #[test]
    fn eip712_domain_separator_is_canonical_per_deployment() {
        let deployment = Deployment {
            chain_id: 42161,
            address: "0x1111111111111111111111111111111111111111".to_string(),
        };
        let context: Context = serde_json::from_value(serde_json::json!({
            "eip712": {
                "deployments": [{
                    "chainId": deployment.chain_id,
                    "address": deployment.address
                }],
                "domain": {
                    "name": "Bound",
                    "version": "1",
                    "chainId": 999,
                    "verifyingContract": "0x9999999999999999999999999999999999999999"
                }
            }
        }))
        .unwrap();
        let (_, contract, got) = resolve_per_deployment(CTX_EIP712, &context, &deployment).unwrap();
        let expected = compute_domain_separator(&Eip712Domain {
            name: Some("Bound".to_string()),
            version: Some("1".to_string()),
            chain_id: Some(42161),
            verifying_contract: Some("0x1111111111111111111111111111111111111111".to_string()),
            salt: None,
        })
        .unwrap();
        assert_eq!(contract, [0x11; 20]);
        assert_eq!(
            got, expected,
            "deployment fields must override domain copies"
        );
    }

    #[test]
    fn strip_param_names_nested_tuple() {
        assert_eq!(
            strip_param_names("((address tokenIn,address tokenOut,uint24 fee) params)"),
            "((address,address,uint24))"
        );
    }

    #[test]
    fn parse_format_key_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        assert_eq!(p.types_signature, "transfer(address,uint256)");
        assert_eq!(p.top_names, vec!["_to".to_string(), "_value".to_string()]);
    }

    #[test]
    fn parse_format_key_nested_tuple() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        assert_eq!(
            p.types_signature,
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(p.top_names, vec!["params".to_string()]);
        let inner = &p.inner_names["params"];
        assert_eq!(inner.len(), 7);
        assert_eq!(inner[0], "tokenIn");
        assert_eq!(inner[4], "amountIn");
    }

    #[test]
    fn parse_format_key_tuple_array_preserves_suffix_and_outer_name() {
        let p = parse_format_key("batchExecute((address to,uint256 value,bytes data)[] calls)")
            .unwrap();
        assert_eq!(p.types_signature, "batchExecute((address,uint256,bytes)[])");
        assert_eq!(p.top_names, vec!["calls".to_string()]);
        assert_eq!(p.top_types, vec!["(address,uint256,bytes)[]".to_string()]);
        assert_eq!(p.inner_names["calls"], ["to", "value", "data"]);
    }

    // ── Duplicate-member-name WYSIWYS guard (adversarial-review finding 2026-07-01) ──

    /// A crafted descriptor with a DUPLICATE tuple-member name is refused. The
    /// Morpho `supply` witness: inner member #1 (`collateralToken`) renamed to a
    /// DUPLICATE of member #0 (`loanToken`). Types are identical (both `address`)
    /// so `strip_param_names` yields the real selector and the descriptor would
    /// dispatch on genuine `supply()` calls — but the name-keyed gates would let
    /// the single `loanToken` field cover BOTH slots, hiding the effect-bearing
    /// `collateralToken` (part of the Morpho market id) behind a trusted clear-sign.
    #[test]
    fn parse_format_key_rejects_duplicate_tuple_member_name() {
        let err = parse_format_key(
            "supply((address loanToken, address loanToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)",
        )
        .expect_err("duplicate tuple-member name must be refused");
        assert!(
            err.contains("duplicate member name"),
            "err names the cause: {err}"
        );
        assert!(err.contains("loanToken"), "err names the dup: {err}");
        // The real, distinct-named Morpho signature still parses.
        assert!(parse_format_key(
            "supply((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)",
        )
        .is_ok());
    }

    /// Symmetric guard: a duplicate TOP-LEVEL argument name is refused too.
    #[test]
    fn parse_format_key_rejects_duplicate_top_level_name() {
        let err = parse_format_key("f(address to, uint256 to)")
            .expect_err("duplicate top-level name must be refused");
        assert!(err.contains("duplicate top-level argument name"), "{err}");
    }

    /// Proves the parse_format_key guard is LOAD-BEARING: if a duplicate-named
    /// tuple ever reached the gates, BOTH `check_contract_field_completeness` and
    /// `check_field_visibility` (name-keyed, position-blind) would WRONGLY accept
    /// it — one `loanToken` field "covers" both inner slots, so the aliased
    /// address at slot 1 is deemed both covered and shown. The gates are
    /// insufficient alone; rejecting duplicates in the parser is what closes it.
    #[test]
    fn dup_member_gates_are_insufficient_without_parse_guard() {
        // Hand-build the ParsedFormatKey the OLD parser produced (dup `loanToken`
        // at inner slots 0 AND 1), bypassing the new guard.
        let s = |x: &str| x.to_string();
        let mut inner_names = BTreeMap::new();
        inner_names.insert(
            s("marketParams"),
            vec![
                s("loanToken"),
                s("loanToken"),
                s("oracle"),
                s("irm"),
                s("lltv"),
            ],
        );
        let mut inner_types = BTreeMap::new();
        inner_types.insert(
            s("marketParams"),
            vec![
                s("address"),
                s("address"),
                s("address"),
                s("address"),
                s("uint256"),
            ],
        );
        let parsed = ParsedFormatKey {
            types_signature: s(
                "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
            ),
            top_names: vec![
                s("marketParams"),
                s("assets"),
                s("shares"),
                s("onBehalf"),
                s("data"),
            ],
            top_types: vec![
                s("(address,address,address,address,uint256)"),
                s("uint256"),
                s("uint256"),
                s("address"),
                s("bytes"),
            ],
            inner_names,
            inner_types,
            struct_defs: BTreeMap::new(), // contract-context: no EIP-712 struct defs
        };
        // The malicious descriptor shows one loanToken field but NO collateralToken.
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams.loanToken","label":"Loan","format":"addressName"},
              {"path":"#.marketParams.oracle","label":"Oracle","format":"addressName"},
              {"path":"#.marketParams.irm","label":"Irm","format":"addressName"},
              {"path":"#.marketParams.lltv","label":"Lltv","format":"raw"},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.data","label":"Data","format":"raw"}
            ]"##,
        );
        // BOTH gates WRONGLY accept — the hole the parse guard closes.
        assert!(
            check_contract_field_completeness("supply(...)", &fmt, &parsed).is_ok(),
            "completeness is name-keyed → one loanToken field covers both slots"
        );
        assert!(
            check_field_visibility("supply(...)", &fmt, &parsed, CTX_CONTRACT).is_ok(),
            "visibility rule 2 is name-keyed → aliased address deemed shown"
        );
    }

    #[test]
    fn compile_path_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        let prog = compile_path("#._value", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 1);
    }

    #[test]
    fn compile_path_nested() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        let prog = compile_path("params.amountIn", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 0); // "params"
        assert_eq!(prog[4], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[5], prog[6]]), 4); // "amountIn"
    }

    // ── Walker slot-confusion fix (head-word slots, not logical ordinals) ──

    /// Sum the `FieldIdx` args of a compiled `#`-rooted program — the
    /// absolute ABI head-word slot the on-device walker resolves to.
    fn head_slot_of(prog: &[u8]) -> u32 {
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        let mut p = 1usize;
        let mut sum = 0u32;
        while p < prog.len() {
            assert_eq!(prog[p], PATHOP_FIELD_IDX, "only FieldIdx ops expected");
            sum += u16::from_be_bytes([prog[p + 1], prog[p + 2]]) as u32;
            p += 3;
        }
        sum
    }

    #[test]
    fn static_head_words_elementary_and_arrays() {
        assert_eq!(static_head_words("address").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("uint256").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("uint8").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("int").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("bytes32").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("bool").unwrap(), HeadWidth::Words(1));
        // Fixed arrays multiply; arrays-of-arrays compound.
        assert_eq!(
            static_head_words("uint256[3]").unwrap(),
            HeadWidth::Words(3)
        );
        assert_eq!(
            static_head_words("address[2]").unwrap(),
            HeadWidth::Words(2)
        );
        assert_eq!(
            static_head_words("uint256[2][3]").unwrap(),
            HeadWidth::Words(6)
        );
        // Static tuple = sum of members.
        assert_eq!(
            static_head_words("(uint256,address,bytes32)").unwrap(),
            HeadWidth::Words(3)
        );
        assert_eq!(
            static_head_words("((uint256,uint256),address)").unwrap(),
            HeadWidth::Words(3)
        );
        // Dynamic types and anything containing them.
        assert_eq!(static_head_words("bytes").unwrap(), HeadWidth::Dynamic);
        assert_eq!(static_head_words("string").unwrap(), HeadWidth::Dynamic);
        assert_eq!(static_head_words("uint256[]").unwrap(), HeadWidth::Dynamic);
        assert_eq!(
            static_head_words("(uint256,bytes)").unwrap(),
            HeadWidth::Dynamic
        );
        assert!(static_head_words("notatype").is_err());
    }

    #[test]
    fn compile_path_multiword_array_predecessor() {
        // The canonical forgery shape: `to` is preceded by a 3-word
        // static array, so its head-word slot is 3 (not logical ordinal 1).
        let p = parse_format_key("f(uint256[3] arr, address to)").unwrap();
        let prog = compile_path("#.to", CTX_CONTRACT, &p).unwrap();
        assert_eq!(head_slot_of(&prog), 3, "to lands at ABI head word 3");
    }

    #[test]
    fn compile_path_non_leading_static_tuple() {
        // `to` follows a 2-word static tuple → head word 2; and a member
        // inside the tuple resolves to its absolute head word.
        let p = parse_format_key("h((uint256 x, uint256 y) s, address to)").unwrap();
        assert_eq!(
            head_slot_of(&compile_path("#.to", CTX_CONTRACT, &p).unwrap()),
            2
        );
        assert_eq!(
            head_slot_of(&compile_path("#.s.y", CTX_CONTRACT, &p).unwrap()),
            1
        );
        assert_eq!(
            head_slot_of(&compile_path("#.s.x", CTX_CONTRACT, &p).unwrap()),
            0
        );
    }

    // ── Nested field-GROUP flattening (Morpho Blue `marketParams`) ──

    /// The Morpho Blue `marketParams` GROUP (a static tuple of 4 addresses +
    /// lltv) flattens to per-member combined paths, and every field — including
    /// the scalars/addresses that land AFTER the 5-word tuple — compiles to its
    /// absolute ABI head-word slot. This is the exact non-leading-static-tuple
    /// slot-confusion case at 5-word width: `assets` MUST resolve to head word
    /// 5, not logical ordinal 1.
    #[test]
    fn flatten_morpho_static_tuple_group_slots() {
        let sig = "borrow((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, address receiver)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams","fields":[
                {"path":"loanToken","label":"Loan","format":"addressName"},
                {"path":"collateralToken","label":"Collat","format":"addressName"},
                {"path":"oracle","label":"Oracle","format":"addressName"},
                {"path":"irm","label":"Irm","format":"addressName"},
                {"path":"lltv","label":"Lltv","format":"raw"}
              ]},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.receiver","label":"Receiver","format":"addressName"}
            ]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).expect("flatten ok");
        let paths: Vec<&str> = flat.iter().map(|f| f.path.as_deref().unwrap()).collect();
        assert_eq!(
            paths,
            vec![
                "#.marketParams.loanToken",
                "#.marketParams.collateralToken",
                "#.marketParams.oracle",
                "#.marketParams.irm",
                "#.marketParams.lltv",
                "#.assets",
                "#.shares",
                "#.onBehalf",
                "#.receiver",
            ],
            "group expands in place, preserving declaration order"
        );
        let slot = |p: &str| head_slot_of(&compile_path(p, CTX_CONTRACT, &parsed).unwrap());
        assert_eq!(slot("#.marketParams.loanToken"), 0);
        assert_eq!(slot("#.marketParams.collateralToken"), 1);
        assert_eq!(slot("#.marketParams.oracle"), 2);
        assert_eq!(slot("#.marketParams.irm"), 3);
        assert_eq!(slot("#.marketParams.lltv"), 4);
        assert_eq!(slot("#.assets"), 5, "assets lands AFTER the 5-word tuple");
        assert_eq!(slot("#.shares"), 6);
        assert_eq!(slot("#.onBehalf"), 7);
        assert_eq!(slot("#.receiver"), 8);
    }

    /// Morpho `supply(... marketParams, assets, shares, onBehalf, bytes data)`:
    /// the dynamic `bytes data` sits at head word 8 (after the 5-word tuple +
    /// three scalars). C1 emits `FieldIdx(8) + FollowOffset` so the device reads
    /// the SAME tail blob the contract decodes — the tuple-width accounting and
    /// the C1 follow must compose correctly.
    #[test]
    fn flatten_morpho_bytes_after_tuple_follows_offset() {
        let sig = "supply((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)";
        let parsed = parse_format_key(sig).unwrap();
        let prog = compile_path("#.data", CTX_CONTRACT, &parsed).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(
            u16::from_be_bytes([prog[2], prog[3]]),
            8,
            "bytes `data` at head word 8 (5-word tuple + assets + shares + onBehalf)"
        );
        assert_eq!(
            prog[4], PATHOP_FOLLOW_OFFSET,
            "dynamic bytes → FollowOffset"
        );
        assert_eq!(prog.len(), 5, "no trailing ops");
    }

    /// Flatten runs BEFORE the completeness + visibility gates (the ordering
    /// that makes the feature real): the flattened Morpho `borrow` fields cover
    /// every marketParams member and surface every address, so both gates pass.
    /// If the ORIGINAL (unflattened) `#.marketParams` group reached the gates,
    /// completeness would reject (`marketParams.loanToken` uncovered) and the
    /// format would blind-sign.
    #[test]
    fn flatten_morpho_borrow_passes_completeness_and_visibility() {
        let sig = "borrow((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, address receiver)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams","fields":[
                {"path":"loanToken","label":"Loan","format":"addressName"},
                {"path":"collateralToken","label":"Collat","format":"addressName"},
                {"path":"oracle","label":"Oracle","format":"addressName"},
                {"path":"irm","label":"Irm","format":"addressName"},
                {"path":"lltv","label":"Lltv","format":"raw"}
              ]},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.receiver","label":"Receiver","format":"addressName"}
            ]"##,
        );
        let flat = Format {
            _id: None,
            intent: Some("Borrow".to_string()),
            fields: flatten_field_groups(&fmt.fields).unwrap(),
            interpolated_intent: None,
            unknown: BTreeMap::new(),
        };
        check_contract_field_completeness(sig, &flat, &parsed)
            .expect("every marketParams member is covered after flatten");
        check_field_visibility(sig, &flat, &parsed, CTX_CONTRACT)
            .expect("every address argument is shown after flatten");
    }

    /// Flatten is the identity on a flat (non-nested) field list — proves the
    /// feature is purely ADDITIVE: a descriptor without groups is byte-for-byte
    /// unchanged, so the corpus delta is exactly the nested-group additions.
    #[test]
    fn flatten_flat_fields_unchanged() {
        let fmt = fmt_from_fields(
            r##"[{"path":"#.to","label":"To","format":"addressName"},
                {"path":"#.amount","label":"Amt","format":"raw"}]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).unwrap();
        let paths: Vec<Option<String>> = flat.iter().map(|f| f.path.clone()).collect();
        assert_eq!(
            paths,
            vec![Some("#.to".to_string()), Some("#.amount".to_string())]
        );
    }

    /// A GROUP anchored on a dynamic array-of-tuples flattens (syntactically) to
    /// `#.orders.[].maker`, but the width-aware compiler REFUSES it — a
    /// per-element tuple-member read is not a static-head access. The flatten
    /// smuggles nothing past the gate; the whole format drops to blind-sign.
    #[test]
    fn flatten_array_of_tuple_group_rejected_by_compiler() {
        // (1) Flatten is purely SYNTACTIC: a GROUP anchored on a dynamic array
        // `#.orders.[]` with a `maker` subfield flattens to the combined
        // per-element path `#.orders.[].maker`.
        let fmt = fmt_from_fields(
            r##"[{"path":"#.orders.[]","fields":[
                  {"path":"maker","label":"Maker","format":"addressName"},
                  {"path":"amount","label":"Amount","format":"raw"}
            ]}]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).expect("flatten is syntactic");
        assert!(
            flat.iter()
                .any(|f| f.path.as_deref() == Some("#.orders.[].maker")),
            "flatten produced the combined per-element path"
        );
        // (2) ...but the width-aware compiler REFUSES an array op in the MIDDLE
        // of a path (a per-element tuple-member read is a dynamic-tail access,
        // not a static-head read), so the format drops to blind-sign — the
        // flatten smuggles nothing past the gate. (An array-of-tuple SIGNATURE
        // is additionally rejected earlier by `parse_format_key`; this pins the
        // compile-level defense that holds even for a parseable outer type.)
        let parsed = parse_format_key("fill(uint256[] orders)").unwrap();
        assert!(
            compile_path("#.orders.[].maker", CTX_CONTRACT, &parsed).is_err(),
            "array op mid-path (per-element member) must be refused by the compiler"
        );
    }

    /// A group with a `fields` sub-array but no anchoring `path` is refused
    /// (nothing for the members to be relative to) — fail-closed.
    #[test]
    fn flatten_group_without_path_rejected() {
        let fmt = fmt_from_fields(r#"[{"fields":[{"path":"x","label":"X","format":"raw"}]}]"#);
        let err = flatten_field_groups(&fmt.fields).expect_err("group needs a path");
        assert!(
            err.contains("no `path`"),
            "error explains the anchor: {err}"
        );
    }

    /// Pathologically deep group nesting is refused, not silently flattened —
    /// a host-stack-safety bound on hostile/malformed descriptors.
    #[test]
    fn flatten_depth_bound_enforced() {
        let mut inner = r#"{"path":"leaf","label":"L","format":"raw"}"#.to_string();
        for _ in 0..(MAX_FIELD_GROUP_DEPTH + 2) {
            inner = format!(r#"{{"path":"g","fields":[{inner}]}}"#);
        }
        let fmt = fmt_from_fields(&format!("[{inner}]"));
        let err = flatten_field_groups(&fmt.fields).expect_err("too-deep nest refused");
        assert!(
            err.contains("MAX_FIELD_GROUP_DEPTH"),
            "error cites the depth bound: {err}"
        );
    }

    #[test]
    fn compile_path_dynamic_bytes_ok_bare_array_rejected() {
        // C1 (FollowOffset resolver): a dynamic `bytes` / `string` field IS now
        // clear-signable — its value sits in the calldata tail and the device
        // follows the offset word to render it (celo `addStorageRoot(bytes url)`
        // / `send(string)`). Was a hard reject before C1.
        let p = parse_format_key("f(bytes data)").unwrap();
        assert!(
            compile_path("#.data", CTX_CONTRACT, &p).is_ok(),
            "C1: dynamic bytes field is clear-signable"
        );
        // A BARE whole dynamic array (no `.[]` render-all) is still rejected — an
        // array is not a single displayable word; use `<arg>.[]` to render its
        // elements (see `compile_array_all_gate`).
        let p = parse_format_key("f(uint256[] xs)").unwrap();
        assert!(
            compile_path("#.xs", CTX_CONTRACT, &p).is_err(),
            "bare whole-array target has no single-word rendering"
        );
    }

    #[test]
    fn compile_path_rejects_multiword_static_target() {
        // A field that is itself multi-word static can't be displayed as a
        // single 32-byte word — refuse rather than show part of it.
        let p = parse_format_key("f(uint256[2] pair, address to)").unwrap();
        assert!(compile_path("#.pair", CTX_CONTRACT, &p).is_err());
    }

    #[test]
    fn compile_path_rejects_array_index_and_unknown_name() {
        let p = parse_format_key("f(uint256[] xs, address to)").unwrap();
        assert!(
            compile_path("#.xs[0]", CTX_CONTRACT, &p).is_err(),
            "array index"
        );
        assert!(
            compile_path("#.nope", CTX_CONTRACT, &p).is_err(),
            "unknown name"
        );
    }

    #[test]
    fn compile_path_rejects_fixed_tuple_array_member_descent() {
        let p =
            parse_format_key("execute((address to,uint256 value)[2] calls,address after)").unwrap();
        for err in [
            compile_path("#.calls.to", CTX_CONTRACT, &p)
                .expect_err("a value path must not select tuple-array element zero"),
            compile_token_path("#.calls.to", CTX_CONTRACT, &p)
                .expect_err("a token path must not select tuple-array element zero"),
        ] {
            assert!(
                err.contains("array"),
                "refusal should name the array shape: {err}"
            );
        }
        assert_eq!(
            head_slot_of(&compile_path("#.after", CTX_CONTRACT, &p).unwrap()),
            4,
            "rejecting descent must not break width accounting past the array"
        );

        let tuple_with_inner_array =
            parse_format_key("f((address[2] prior,address selected) cfg)").unwrap();
        assert_eq!(
            head_slot_of(
                &compile_path("#.cfg.selected", CTX_CONTRACT, &tuple_with_inner_array).unwrap()
            ),
            2,
            "an array inside an ordinary tuple is handled by width accounting, not rejected"
        );
    }

    #[test]
    fn eip712_token_path_rejects_unknown_name() {
        let p = parse_format_key("Permit(address token,uint256 amount)").unwrap();
        assert_eq!(
            &keccak256(b"ghost6140")[..2],
            &[0, 0],
            "collision witness must alias ordinal zero under the removed fallback"
        );
        let err = compile_token_path("ghost6140", CTX_EIP712, &p)
            .expect_err("an unknown typed-data name must not compile as a truncated hash");
        assert!(
            err.contains("ghost6140") && err.contains("not in"),
            "refusal should name the unknown member: {err}"
        );
        assert_eq!(
            compile_token_path("token", CTX_EIP712, &p).unwrap(),
            [PATHOP_ROOT_STRUCT, PATHOP_FIELD_IDX, 0, 0],
            "a declared field-zero token path keeps its exact wire bytes"
        );
    }

    #[test]
    fn token_paths_require_exact_address_endpoints_or_checked_extraction() {
        let p =
            parse_format_key("f(uint256 amount,bool flag,address token,address[] route)").unwrap();
        for invalid in ["flag", "route.[]"] {
            let err = compile_token_path(invalid, CTX_CONTRACT, &p)
                .expect_err("a non-scalar or multi-value endpoint is not one token identity");
            assert!(err.contains("token identity"), "{invalid}: {err}");
        }
        assert!(
            compile_token_path("route", CTX_CONTRACT, &p).is_err(),
            "a bare dynamic array is not a token identity either"
        );
        assert!(compile_token_path("token", CTX_CONTRACT, &p).is_ok());
        assert!(compile_token_path("route.[0]", CTX_CONTRACT, &p).is_ok());
        assert_eq!(
            compile_token_path("@.to", CTX_CONTRACT, &p).unwrap(),
            NFT_COLLECTION_TO_PATH,
            "the authenticated target-address identity remains supported"
        );
    }

    #[test]
    fn eip712_format_rejects_unknown_token_path_end_to_end() {
        let sig = "Permit(address token,uint256 amount)";
        let fmt = fmt_from_fields(
            r#"[
              {"path":"token","label":"Token","format":"addressName"},
              {"path":"amount","label":"Amount","format":"tokenAmount",
               "params":{"tokenPath":"ghost6140"}}
            ]"#,
        );
        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        let err = compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect_err("an otherwise-complete format must reject a typo/collision tokenPath");
        assert!(err.contains("ghost6140") && err.contains("not in"), "{err}");
    }

    // ── Tier B: tokenPath byte-slice / array-index (tokenPath-ONLY) ──────────
    #[test]
    fn token_path_slice_ops_are_tokenpath_only() {
        // The load-bearing invariant: a slice / index op compiles as a
        // `tokenPath` (token id inside a dynamic leg) but is REFUSED in a
        // rendered VALUE path — showing one element/slice of a value hides the
        // rest (array-tail-hiding WYSIWYS hazard) and for an address would be a
        // wrong recipient. This is exactly what keeps paraswap `pools.[-1]` /
        // `beneficiaryAndApproveFlag.[-20:]` (rendered ADDRESS values) declined
        // even after Tier B enabled slice parsing.
        let p = parse_format_key("exactInput(bytes path, uint256 amountIn)").unwrap();
        assert!(
            compile_token_path("path.[0:20]", CTX_CONTRACT, &p).is_ok(),
            "tokenPath [0:20]"
        );
        assert!(
            compile_token_path("path.[-20:]", CTX_CONTRACT, &p).is_ok(),
            "tokenPath [-20:]"
        );
        assert!(
            compile_path("path.[0:20]", CTX_CONTRACT, &p).is_err(),
            "VALUE slice refused"
        );
        assert!(
            compile_path("path.[-20:]", CTX_CONTRACT, &p).is_err(),
            "VALUE tail slice refused"
        );

        let a = parse_format_key("swap(uint256 amountIn, address[] path)").unwrap();
        assert!(
            compile_token_path("path.[0]", CTX_CONTRACT, &a).is_ok(),
            "tokenPath [0]"
        );
        assert!(
            compile_token_path("path.[-1]", CTX_CONTRACT, &a).is_ok(),
            "tokenPath [-1]"
        );
        assert!(
            compile_path("path.[0]", CTX_CONTRACT, &a).is_err(),
            "VALUE index refused"
        );
        assert!(
            compile_path("path.[-1]", CTX_CONTRACT, &a).is_err(),
            "VALUE last refused"
        );
    }

    #[test]
    fn token_path_slice_width_and_type_guards() {
        // Only a 20-byte ADDRESS slice — rejects paraswap's 32-byte word slices
        // (`#.data.[292:324]`) and 1inch's 4-byte timestamp tail (`goodUntil.[-4:]`).
        let b = parse_format_key("f(bytes data)").unwrap();
        assert!(
            compile_token_path("data.[0:20]", CTX_CONTRACT, &b).is_ok(),
            "20-byte slice ok"
        );
        assert!(
            compile_token_path("data.[292:324]", CTX_CONTRACT, &b).is_err(),
            "32-byte word slice refused"
        );
        assert!(
            compile_token_path("data.[0:16]", CTX_CONTRACT, &b).is_err(),
            "non-20 slice refused"
        );
        assert!(
            compile_token_path("data.[-4:]", CTX_CONTRACT, &b).is_err(),
            "4-byte tail refused"
        );

        // Container-type discipline: slice needs dynamic `bytes`, index needs
        // dynamic `address[]` (not a scalar, not `uint256[]`, not a fixed array).
        let s = parse_format_key("g(uint256 x)").unwrap();
        assert!(
            compile_token_path("x.[0:20]", CTX_CONTRACT, &s).is_err(),
            "slice on scalar refused"
        );
        let u = parse_format_key("h(uint256[] xs)").unwrap();
        assert!(
            compile_token_path("xs.[0]", CTX_CONTRACT, &u).is_err(),
            "non-address element refused"
        );
        let fx = parse_format_key("k(address[3] fixd)").unwrap();
        assert!(
            compile_token_path("fixd.[0]", CTX_CONTRACT, &fx).is_err(),
            "fixed array refused"
        );
    }

    #[test]
    fn token_path_slice_emits_terminal_extraction_op() {
        let p = parse_format_key("exactInput(bytes path, uint256 amountIn)").unwrap();
        let prog = compile_token_path("path.[0:20]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert!(
            prog.contains(&PATHOP_FOLLOW_OFFSET),
            "FollowOffset into the bytes region"
        );
        assert!(prog.contains(&PATHOP_ARRAY_SLICE), "ArraySlice op emitted");
        assert_eq!(*prog.last().unwrap(), 0x00, "[0:20] from_end flag = 0");
        let progl = compile_token_path("path.[-20:]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(*progl.last().unwrap(), 0x01, "[-20:] from_end flag = 1");

        let a = parse_format_key("swap(uint256 amountIn, address[] path)").unwrap();
        assert!(compile_token_path("path.[0]", CTX_CONTRACT, &a)
            .unwrap()
            .contains(&PATHOP_ARRAY_IDX));
        assert_eq!(
            *compile_token_path("path.[-1]", CTX_CONTRACT, &a)
                .unwrap()
                .last()
                .unwrap(),
            PATHOP_ARRAY_LAST
        );
    }

    // Byte-exact compile→device round-trip on the FROZEN tokenPath wire format.
    // dbgen `compile_token_path` and the device `resolve::resolve_token_address`
    // are two halves of one on-chain-adjacent contract: any one-sided wire edit
    // (reorder ArraySlice start/len, flip from_end, change ArrayIdx width) is a
    // confirm-vs-execute desync. This test compiles the real shapes and resolves
    // the SAME bytes on the device side against a hand-built body, asserting the
    // extracted 20-byte address — so a one-sided edit fails here even if both the
    // dbgen-shape tests and the device unit tests still pass on their own.
    #[test]
    fn token_path_compile_device_round_trip() {
        use pqsigner_erc7730::render::resolve::resolve_token_address;

        fn word(bytes32: [u8; 32]) -> [u8; 32] {
            bytes32
        }
        fn u(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }
        fn addr_word(a: [u8; 20]) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&a);
            w
        }
        // Resolve a compiled program (strip the RootStructured byte) on the device.
        fn resolve(prog: &[u8], body: &[u8]) -> [u8; 20] {
            assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
            resolve_token_address(&prog[1..], body).expect("device resolves the compiled program")
        }

        let t_in = [0x11u8; 20];
        let t_out = [0x22u8; 20];
        let t_mid = [0xABu8; 20];

        // C1 packed path: one top-level dynamic `bytes` argument owns the
        // entire canonical tail → [0:20]/[-20:].
        let p = parse_format_key(
            "exactInput(bytes path,address recipient,uint256 amountIn,uint256 amountOutMinimum)",
        )
        .unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&u(128)); // [0]   offset to path
        body.extend_from_slice(&addr_word([0x33; 20])); // [32]  recipient
        body.extend_from_slice(&u(1)); // [64]  amountIn
        body.extend_from_slice(&u(2)); // [96] amountOutMinimum
        body.extend_from_slice(&u(43)); // [128] path len = 20+3+20
        let mut packed = Vec::new();
        packed.extend_from_slice(&t_in);
        packed.extend_from_slice(&[0x00, 0x0b, 0xb8]); // fee
        packed.extend_from_slice(&t_out);
        while packed.len() % 32 != 0 {
            packed.push(0);
        }
        body.extend_from_slice(&packed); // [160] packed path

        let prog_in = compile_token_path("path.[0:20]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(resolve(&prog_in, &body), t_in, "[0:20] → input token");
        let prog_out = compile_token_path("path.[-20:]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(resolve(&prog_out, &body), t_out, "[-20:] → output token");

        // C2 negative control: the same bytes nested inside a dynamic tuple is
        // no longer emitted because compact IR lacks tuple-local tail topology.
        let c2 = parse_format_key(
            "exactInput((bytes path,address recipient,uint256 amountIn,uint256 amountOutMinimum) params)",
        )
        .unwrap();
        assert!(
            compile_token_path("params.path.[0:20]", CTX_CONTRACT, &c2).is_err(),
            "dynamic-tuple tokenPath descent must fail closed"
        );

        // swapExactTokensForTokens: address[] path → [0] / [-1] (3-hop).
        let s =
            parse_format_key("swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to)")
                .unwrap();
        let mut sbody = Vec::new();
        sbody.extend_from_slice(&u(1)); // [0]  amountIn
        sbody.extend_from_slice(&u(2)); // [32] amountOutMin
        sbody.extend_from_slice(&u(128)); // [64] offset to path array
        sbody.extend_from_slice(&addr_word([0x33; 20])); // [96] to
        sbody.extend_from_slice(&u(3)); // [128] count = 3
        sbody.extend_from_slice(&addr_word(t_in)); // [160] path[0]
        sbody.extend_from_slice(&addr_word(t_mid)); // [192] path[1]
        sbody.extend_from_slice(&addr_word(t_out)); // [224] path[2]

        let prog_first = compile_token_path("path.[0]", CTX_CONTRACT, &s).unwrap();
        assert_eq!(resolve(&prog_first, &sbody), t_in, "[0] → first element");
        let prog_last = compile_token_path("path.[-1]", CTX_CONTRACT, &s).unwrap();
        assert_eq!(
            resolve(&prog_last, &sbody),
            t_out,
            "[-1] → last element (3-hop, not middle)"
        );

        // Static tokenPath (no extraction op): a plain `address` argument.
        let f = parse_format_key("g(address token)").unwrap();
        let gbody = word(addr_word(t_in));
        let prog_static = compile_token_path("token", CTX_CONTRACT, &f).unwrap();
        assert_eq!(resolve(&prog_static, &gbody), t_in, "static address word");
    }

    #[test]
    fn compile_array_all_gate() {
        // ACCEPT: `<arg>.[]` render-all on a top-level dynamic array of a
        // static primitive → FieldIdx(offset-slot) + ArrayAll.
        let p = parse_format_key("requestWithdrawals(uint256[] _amounts, address _owner)").unwrap();
        let prog = compile_path("_amounts.[]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(
            u16::from_be_bytes([prog[2], prog[3]]),
            0,
            "_amounts is arg 0"
        );
        assert_eq!(prog[4], PATHOP_ARRAY_ALL);
        assert_eq!(prog.len(), 5, "Root + one FieldIdx + ArrayAll");

        // REFUSE: single-index / last (array-tail-hiding — would show a subset).
        assert!(
            compile_path("_amounts[0]", CTX_CONTRACT, &p).is_err(),
            "single index"
        );
        assert!(
            compile_path("_amounts[-1]", CTX_CONTRACT, &p).is_err(),
            "last"
        );

        // Multi-tail keeps the exact same field-local program. Runtime obtains
        // the array interval from the separately authenticated topology; dbgen
        // must not invent a FollowOffset+ArrayAll dialect.
        let two_dyn = parse_format_key("f(uint256[] a, bytes b)").unwrap();
        let multi_prog = compile_path("a.[]", CTX_CONTRACT, &two_dyn).unwrap();
        assert_eq!(multi_prog, prog);
        assert!(!multi_prog.contains(&PATHOP_FOLLOW_OFFSET));

        // REFUSE: dynamic element type (`string[]`) and nested array (`uint256[][]`).
        let dyn_elem = parse_format_key("f(string[] xs)").unwrap();
        assert!(
            compile_path("xs.[]", CTX_CONTRACT, &dyn_elem).is_err(),
            "dynamic element"
        );
        let nested = parse_format_key("f(uint256[][] xs)").unwrap();
        assert!(
            compile_path("xs.[]", CTX_CONTRACT, &nested).is_err(),
            "nested array"
        );

        // REFUSE: array op in EIP-712 / envelope context (gate-hardening — `[]`
        // is contract-calldata-only; EIP-712 encodeData has no dynamic tail).
        assert!(
            compile_path("xs.[]", CTX_EIP712, &dyn_elem).is_err(),
            "eip712 array"
        );
        let any = parse_format_key("Order(uint256[] notes, address owner)").unwrap();
        assert!(
            compile_path("notes.[]", CTX_EIP712, &any).is_err(),
            "eip712 array (uint)"
        );
    }

    #[test]
    fn dynamic_tail_topology_derives_exact_blob_payload() {
        let parsed = parse_format_key("f(bytes payload,string note)").unwrap();
        assert_eq!(
            derive_dynamic_tail_topology(&parsed).unwrap(),
            Some(vec![
                TOPOLOGY_VERSION,
                2,
                0,
                0,
                TAIL_KIND_BLOB,
                0,
                1,
                TAIL_KIND_BLOB,
            ])
        );

        for legacy in ["f(uint256 value)", "f(string note)"] {
            let parsed = parse_format_key(legacy).unwrap();
            assert_eq!(
                derive_dynamic_tail_topology(&parsed).unwrap(),
                None,
                "static and sole-tail formats must not gain a marker: {legacy}"
            );
        }
    }

    #[test]
    fn dynamic_tail_topology_uses_absolute_slots_and_mixed_kinds() {
        // bytes occupies slot 0; the fixed array spans slots 1..3; address[]
        // therefore occupies offset slot 3 and the final string slot 4.
        let parsed = parse_format_key(
            "f(bytes payload,uint256[2] fixedWords,address[] recipients,string note)",
        )
        .unwrap();
        assert_eq!(
            derive_dynamic_tail_topology(&parsed).unwrap(),
            Some(vec![
                TOPOLOGY_VERSION,
                3,
                0,
                0,
                TAIL_KIND_BLOB,
                0,
                3,
                TAIL_KIND_STATIC_WORD_ARRAY,
                0,
                4,
                TAIL_KIND_BLOB,
            ])
        );
    }

    #[test]
    fn dynamic_tail_topology_caps_count_and_rejects_unsupported_kinds() {
        let too_many = parse_format_key("f(bytes a,string b,bytes c,string d,bytes e)").unwrap();
        let error =
            derive_dynamic_tail_topology(&too_many).expect_err("cap plus one must fail closed");
        assert!(
            error.contains("5 dynamic top-level arguments") && error.contains("topology cap"),
            "unexpected cap refusal: {error}"
        );

        for signature in [
            "f(bytes a,(uint256 value,bytes note) cfg)",
            "f(bytes a,bytes[] values)",
            "f(bytes a,uint256[][] values)",
            "f(bytes a,bytes[2] values)",
            "f(bytes a,(uint256 value,address owner)[] values)",
        ] {
            let parsed = parse_format_key(signature).unwrap();
            let error = derive_dynamic_tail_topology(&parsed)
                .expect_err("unsupported dynamic kind must fail closed");
            assert!(
                error.contains("unsupported by authenticated multi-tail topology"),
                "unexpected refusal for {signature}: {error}"
            );
        }
    }

    #[test]
    fn compiler_emits_multi_tail_marker_only_on_field_zero() {
        let fmt = fmt_from_fields(
            r#"[
                {"path":"first","label":"First","format":"raw"},
                {"path":"second","label":"Second","format":"raw"}
            ]"#,
        );
        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        compile_one_format(
            "f(string first,string second)",
            &fmt,
            CTX_CONTRACT,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect("supported two-tail format compiles");
        let offsets = contract_format_param_offsets(&out);
        let expected = [
            TOPOLOGY_VERSION,
            2,
            0,
            0,
            TAIL_KIND_BLOB,
            0,
            1,
            TAIL_KIND_BLOB,
        ];
        assert_eq!(
            find_tlv(&pool, offsets[0], PARAM_DYNAMIC_TAIL_TOPOLOGY),
            Some(expected.as_slice())
        );
        assert_eq!(
            find_tlv(&pool, offsets[1], PARAM_DYNAMIC_TAIL_TOPOLOGY),
            None,
            "the format-level marker is placement-pinned to field zero"
        );

        let sole_fmt = fmt_from_fields(r#"[{"path":"only","label":"Only","format":"raw"}]"#);
        let mut sole_pool = Pool::new();
        let mut sole_out = Vec::new();
        compile_one_format(
            "f(string only)",
            &sole_fmt,
            CTX_CONTRACT,
            &mut test_ctx(),
            &mut sole_pool,
            &BTreeMap::new(),
            &mut sole_out,
            None,
        )
        .expect("legacy sole-tail format compiles");
        let sole_offsets = contract_format_param_offsets(&sole_out);
        assert_eq!(
            find_tlv(&sole_pool, sole_offsets[0], PARAM_DYNAMIC_TAIL_TOPOLOGY),
            None,
            "legacy sole-tail output must not carry the new marker"
        );
    }

    #[test]
    fn multi_tail_paths_reuse_bounded_ops_but_c2_and_value_indexes_stay_refused() {
        let multi = parse_format_key("f(string text,address[] route)").unwrap();
        assert!(compile_path("text", CTX_CONTRACT, &multi).is_ok());
        assert!(compile_token_path("route.[-1]", CTX_CONTRACT, &multi).is_ok());
        assert!(compile_path("route.[]", CTX_CONTRACT, &multi).is_ok());
        assert!(compile_path("route[0]", CTX_CONTRACT, &multi).is_err());

        let c2 =
            parse_format_key("setConfig((uint256 amount,address token,bytes note) cfg)").unwrap();
        assert!(
            compile_path("cfg.amount", CTX_CONTRACT, &c2).is_err(),
            "even a static member of a dynamic tuple needs unavailable C2 topology"
        );
        assert!(
            compile_token_path("cfg.token", CTX_CONTRACT, &c2).is_err(),
            "tokenPath must not descend through a dynamic tuple"
        );

        let static_tuple =
            parse_format_key("setConfig((uint256 amount,address token) cfg)").unwrap();
        assert!(compile_path("cfg.amount", CTX_CONTRACT, &static_tuple).is_ok());
        assert!(compile_token_path("cfg.token", CTX_CONTRACT, &static_tuple).is_ok());
    }

    #[test]
    fn per_format_tolerance_keeps_compilable_drops_unrenderable() {
        use serde_json::json;
        // `transfer(...)` compiles; the `swap` format's single-index array
        // path does NOT (single index is refused — array-tail-hiding).
        let display: Display = serde_json::from_value(json!({
            "formats": {
                "transfer(address to, uint256 value)": {
                    "intent": "Send",
                    "fields": [
                        { "path": "to", "label": "To", "format": "raw" },
                        { "path": "value", "label": "Amount", "format": "raw" }
                    ]
                },
                "swap(uint256[] amounts)": {
                    "intent": "Swap",
                    "fields": [ { "path": "amounts[0]", "label": "Amt", "format": "raw" } ]
                }
            }
        }))
        .unwrap();
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            eip712_word_guard_source_required: false,
        };
        // STRICT: the unrenderable `swap` fails the WHOLE descriptor.
        assert!(compile_formats(&display, CTX_CONTRACT, &mut ctx, false).is_err());
        // TOLERANT: keep the renderable `transfer`, drop `swap` → 1 format,
        // while preserving the exact overloaded signature in the receipt.
        let mut drops = Vec::new();
        let (buf, _pool) = compile_formats_reporting(
            &display,
            CTX_CONTRACT,
            &mut ctx,
            true,
            &mut drops,
            None,
            None,
        )
        .unwrap();
        assert_eq!(buf[0], 1, "exactly one surviving format (transfer)");
        assert_eq!(drops.len(), 1);
        assert!(drops[0].contains("swap(uint256[] amounts)"), "{:?}", drops);
    }

    #[test]
    fn compile_path_dynamic_predecessor_still_resolves_static_target() {
        // A dynamic predecessor occupies exactly one head (offset) word, so
        // a later static field sits at a fixed head slot and is readable.
        let p = parse_format_key("f(bytes blob, address to)").unwrap();
        assert_eq!(
            head_slot_of(&compile_path("#.to", CTX_CONTRACT, &p).unwrap()),
            1
        );
    }

    #[test]
    fn format_static_head_words_contract_and_eip712() {
        let p = parse_format_key("f(uint256[3] arr, address to)").unwrap();
        assert_eq!(format_static_head_words(CTX_CONTRACT, &p).unwrap(), 4);
        // EIP-712: every top-level member is one encodeData word.
        let p = parse_format_key("Order(address maker, uint256[3] nums, address taker)").unwrap();
        assert_eq!(format_static_head_words(CTX_EIP712, &p).unwrap(), 3);
    }

    #[test]
    fn eip712_path_keeps_logical_ordinal() {
        // EIP-712 `encodeData` is one word per member regardless of ABI
        // width, so the message-root path stays a logical ordinal — the
        // width-aware contract logic must NOT apply here.
        let p = parse_format_key("Order(address maker, uint256[3] nums, address taker)").unwrap();
        let prog = compile_path("#.taker", CTX_EIP712, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(
            u16::from_be_bytes([prog[2], prog[3]]),
            2,
            "ordinal 2, not width 4"
        );
    }

    #[test]
    fn container_path_keeps_keccak_discriminator() {
        // `@.value` must still encode the keccak-prefix discriminator the
        // on-device envelope resolver matches — the width logic only
        // governs `#` calldata roots, and envelope field names (`value`,
        // `to`, …) are not calldata args here so the discriminator fires.
        let p = parse_format_key("deposit()").unwrap();
        let prog = compile_path("@.value", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_CONTAINER);
        let disc = u16::from_be_bytes([prog[2], prog[3]]);
        let h = keccak256(b"value");
        assert_eq!(disc, u16::from_be_bytes([h[0], h[1]]));

        // ABI argument names must never shadow the independent `@` namespace.
        let colliding = parse_format_key("approve(address to,uint256 tokenId)").unwrap();
        assert_eq!(
            compile_path("@.to", CTX_CONTRACT, &colliding).unwrap(),
            [
                pqsigner_erc7730::ir::PathOp::RootContainer as u8,
                pqsigner_erc7730::ir::PathOp::FieldIdx as u8,
                (pqsigner_erc7730::abi::container_field::TO >> 8) as u8,
                pqsigner_erc7730::abi::container_field::TO as u8,
            ],
            "calldata `to` cannot shadow envelope `@.to`"
        );

        // `@.from` is a frozen cross-host/device wire contract. Keep the exact
        // program bytes explicit because enabling the device renderer must not
        // silently change the descriptor database schema or field identity.
        let from = compile_path("@.from", CTX_CONTRACT, &p).unwrap();
        assert_eq!(
            from,
            [
                pqsigner_erc7730::ir::PathOp::RootContainer as u8,
                pqsigner_erc7730::ir::PathOp::FieldIdx as u8,
                (pqsigner_erc7730::abi::container_field::FROM >> 8) as u8,
                pqsigner_erc7730::abi::container_field::FROM as u8,
            ]
        );
    }

    #[test]
    fn jcs_object_keys_sorted() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2,"c":[1,2]}"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"{"a":2,"b":1,"c":[1,2]}"#);
    }

    #[test]
    fn jcs_string_escapes() {
        let v: serde_json::Value = serde_json::Value::String("a\"b\\c\n".to_string());
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#""a\"b\\c\n""#);
    }

    #[test]
    fn jcs_array_in_doc_order() {
        let v: serde_json::Value = serde_json::from_str(r#"[3,1,2]"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"[3,1,2]"#);
    }

    #[test]
    fn jcs_rejects_integers_outside_the_exact_ieee754_safe_range() {
        let positive_edge: serde_json::Value = serde_json::from_str(r#"9007199254740991"#).unwrap();
        assert_eq!(
            jcs_canonicalize(&positive_edge).unwrap(),
            b"9007199254740991"
        );
        let negative_edge: serde_json::Value =
            serde_json::from_str(r#"-9007199254740991"#).unwrap();
        assert_eq!(
            jcs_canonicalize(&negative_edge).unwrap(),
            b"-9007199254740991"
        );

        for ambiguous in [r#"9007199254740993"#, r#"-9007199254740993"#] {
            let value: serde_json::Value = serde_json::from_str(ambiguous).unwrap();
            let error = jcs_canonicalize(&value)
                .expect_err("JCS subset must not hash an integer ECMAScript would round");
            assert!(error.contains("exact IEEE-754 safe range"), "{error}");
        }
    }

    /// ERC-8176 `descriptorHash` = keccak256(RFC-8785 JCS(descriptor)). Golden
    /// vectors whose keccak values were computed INDEPENDENTLY (foundry
    /// `cast keccak` over the canonical JCS string) — so this locks our JCS +
    /// keccak against a third-party implementation, which is what makes our hash
    /// byte-match what an auditor attests on EAS. (Additionally cross-validated
    /// end-to-end on a real registry descriptor: `ledgerquest/eip712-ledgerquest`
    /// → 0x16a312e2…acad… via both dbgen and python-JCS+`cast keccak`.)
    #[test]
    fn erc8176_hash_golden_vectors() {
        use pqsigner_tx_core::hash::keccak256;
        // Key sort (b→a becomes a,b), array order preserved, integers.
        let v: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":[1,"x"]}"#).unwrap();
        let jcs = jcs_canonicalize(&v).unwrap();
        assert_eq!(jcs, br#"{"a":[1,"x"],"b":2}"#);
        assert_eq!(
            hex::encode(keccak256(&jcs)),
            "6fc0cf5686e5292611ba7b595e551c0e49fe88c20fc60a5820e22acdb010beb1"
        );
        // String escaping: value a"b\c → "a\"b\\c".
        let v2: serde_json::Value = serde_json::from_str(r#"{"s":"a\"b\\c"}"#).unwrap();
        let jcs2 = jcs_canonicalize(&v2).unwrap();
        assert_eq!(jcs2, br#"{"s":"a\"b\\c"}"#);
        assert_eq!(
            hex::encode(keccak256(&jcs2)),
            "8cd0880e152d264b68eecb43ff71f6978922ea7234ca7b5fde387f68b744ee2a"
        );
    }

    #[test]
    fn build_db_seed_corpus() {
        // Find the repo's secure/data/erc7730 directory relative to
        // CARGO_MANIFEST_DIR (dbgen/).
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = root.join("secure/data/erc7730");
        let policy = dir.join("policy.toml");
        let res = build_db(&dir, &policy).expect("build seed corpus");
        // `secure/data/erc7730/` is now a synthetic-only render-test corpus
        // (the protocol fixtures were duplicates of the vendored registry —
        // the PROD corpus built tolerantly elsewhere), so the floor is ≥1.
        assert!(
            res.leaf_count >= 1,
            "expected ≥1 leaf, got {}",
            res.leaf_count
        );
        round_trip_check(&res).expect("round-trip");
    }

    // ── Audit H-3 — field-completeness lint (clear-sign forgery class) ──
    //
    // A descriptor that silently omits an effect-bearing calldata word
    // renders a benign page while the signature still commits to the
    // hidden value. These pin both the top-level rule and the tuple-member
    // tightening (the renderer addresses static-tuple members individually,
    // so per-member coverage is required — not "tuple touched once").

    /// Build a throwaway `Format` from a JSON `fields` array.
    fn fmt_from_fields(fields_json: &str) -> Format {
        serde_json::from_str(&format!(r#"{{"fields": {fields_json}}}"#))
            .expect("valid test Format JSON")
    }

    // ── review finding 1.1: field-level $ref → $.display.definitions ─────
    // Direct unit tests of the resolver's merge rule + its fail-loud error
    // paths (the render-level proof lives in the secure crate's render tests).

    fn resolve_fmt_refs(display_json: &str, fmt_key: &str) -> Result<Vec<FieldDef>, String> {
        let display: Display = serde_json::from_str(display_json).expect("valid display JSON");
        let fmt = display.formats.get(fmt_key).expect("format present");
        resolve_display_refs(&fmt.fields, display.definitions.as_ref())
    }

    #[test]
    fn ref_resolution_merges_format_from_def_and_params_field_wins() {
        let display = r#"{
            "definitions": {
                "sendAmount": { "label": "Amount to Send", "format": "tokenAmount",
                                "params": { "nativeCurrencyAddress": ["0xeee"] } }
            },
            "formats": { "swap(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.sendAmount", "path": "a",
                  "params": { "tokenPath": "src" } }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "swap(uint256 a)").expect("resolves");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(
            f.format.as_deref(),
            Some("tokenAmount"),
            "format ALWAYS from def"
        );
        assert_eq!(
            f.label.as_deref(),
            Some("Amount to Send"),
            "label inherited from def"
        );
        assert_eq!(f.path.as_deref(), Some("a"), "path from the reference");
        let p = f.params.as_ref().expect("merged params");
        assert!(
            p.get("nativeCurrencyAddress").is_some(),
            "def param survives merge"
        );
        assert_eq!(
            p.get("tokenPath").and_then(|v| v.as_str()),
            Some("src"),
            "field param survives merge (per-key, field wins)"
        );
        assert!(f.ref_def.is_none(), "the $ref key is consumed");
    }

    #[test]
    fn ref_resolution_field_label_overrides_definition() {
        let display = r#"{
            "definitions": { "amt": { "label": "Amount to Receive", "format": "tokenAmount" } },
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.amt", "path": "a", "label": "Min Out" }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "f(uint256 a)").expect("resolves");
        assert_eq!(
            out[0].label.as_deref(),
            Some("Min Out"),
            "field label overrides def"
        );
        assert_eq!(out[0].format.as_deref(), Some("tokenAmount"));
    }

    #[test]
    fn ref_resolution_unresolvable_ref_hard_errors() {
        // No such definition → fail LOUD (never silently degrade to raw).
        let display = r#"{
            "definitions": { "other": { "format": "tokenAmount" } },
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.missing", "path": "a" }
            ] } }
        }"#;
        let err = resolve_fmt_refs(display, "f(uint256 a)").unwrap_err();
        assert!(err.contains("unresolved $ref"), "got: {err}");
    }

    #[test]
    fn ref_resolution_non_display_definition_ref_hard_errors() {
        // A field-level $ref must target $.display.definitions.* — an enum
        // ($.metadata.enums.*) ref at the field level is malformed → error,
        // not a silent drop.
        let display = r#"{
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.metadata.enums.mode", "path": "a" }
            ] } }
        }"#;
        let err = resolve_fmt_refs(display, "f(uint256 a)").unwrap_err();
        assert!(err.contains("not a `$.display.definitions"), "got: {err}");
    }

    #[test]
    fn ref_resolution_no_ref_is_identity() {
        let display = r#"{
            "formats": { "f(uint256 a)": { "fields": [
                { "path": "a", "label": "A", "format": "raw" }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "f(uint256 a)").expect("resolves");
        assert_eq!(out[0].format.as_deref(), Some("raw"));
        assert_eq!(out[0].label.as_deref(), Some("A"));
    }

    // ── review 5.3: single-source the wire vocabulary ───────────────────
    /// The dbgen-local `PATHOP_*`/`FMT_*`/`PARAM_*`/`VIS_*` constants are
    /// "mirrored by comment discipline" from the on-device `pqsigner_erc7730`
    /// enums. Pin them to the crate so a silent divergence — the exact
    /// confirm-vs-execute desync class the walker header warns about — fails CI
    /// instead of shipping a mis-encoded IR into the trusted root.
    #[test]
    fn wire_vocab_single_sourced_from_crate() {
        use pqsigner_erc7730::ir::{FormatOp, PathOp, Visibility};
        use pqsigner_erc7730::render::params;

        // Path opcodes.
        assert_eq!(PATHOP_ROOT_STRUCT, PathOp::RootStructured as u8);
        assert_eq!(PATHOP_ROOT_CONTAINER, PathOp::RootContainer as u8);
        assert_eq!(PATHOP_ROOT_METADATA, PathOp::RootMetadata as u8);
        assert_eq!(PATHOP_FIELD_IDX, PathOp::FieldIdx as u8);
        assert_eq!(PATHOP_ARRAY_IDX, PathOp::ArrayIdx as u8);
        assert_eq!(PATHOP_ARRAY_SLICE, PathOp::ArraySlice as u8);
        assert_eq!(PATHOP_ARRAY_LAST, PathOp::ArrayLast as u8);
        assert_eq!(PATHOP_ARRAY_ALL, PathOp::ArrayAll as u8);
        assert_eq!(PATHOP_FOLLOW_OFFSET, PathOp::FollowOffset as u8);

        // Formatter opcodes.
        assert_eq!(FMT_RAW, FormatOp::Raw as u8);
        assert_eq!(FMT_AMOUNT, FormatOp::Amount as u8);
        assert_eq!(FMT_TOKEN_AMOUNT, FormatOp::TokenAmount as u8);
        assert_eq!(FMT_NFT_NAME, FormatOp::NftName as u8);
        assert_eq!(FMT_DATE, FormatOp::Date as u8);
        assert_eq!(FMT_DURATION, FormatOp::Duration as u8);
        assert_eq!(FMT_ADDRESS_NAME, FormatOp::AddressName as u8);
        assert_eq!(FMT_ENUM, FormatOp::Enum as u8);
        assert_eq!(FMT_UNIT, FormatOp::Unit as u8);
        assert_eq!(FMT_CALLDATA, FormatOp::Calldata as u8);
        assert_eq!(FMT_CHAIN_ID, FormatOp::ChainId as u8);
        assert_eq!(FMT_TOKEN_TICKER, FormatOp::TokenTicker as u8);
        assert_eq!(
            FMT_INTEROP_ADDR_NAME,
            FormatOp::InteroperableAddressName as u8
        );
        assert_eq!(FMT_ENCRYPTED, FormatOp::Encrypted as u8);
        assert_eq!(FMT_UNISWAP_V3_PATH, FormatOp::UniswapV3Path as u8);

        // Param TLV tags.
        assert_eq!(PARAM_TOKEN_PATH, params::PARAM_TOKEN_PATH);
        assert_eq!(PARAM_TOKEN, params::PARAM_TOKEN);
        assert_eq!(PARAM_THRESHOLD, params::PARAM_THRESHOLD);
        assert_eq!(PARAM_MESSAGE, params::PARAM_MESSAGE);
        assert_eq!(PARAM_ADDR_TYPES, params::PARAM_ADDR_TYPES);
        assert_eq!(PARAM_ADDR_SOURCES, params::PARAM_ADDR_SOURCES);
        assert_eq!(PARAM_DATE_ENCODING, params::PARAM_DATE_ENCODING);
        assert_eq!(PARAM_ENUM_REF, params::PARAM_ENUM_REF);
        assert_eq!(PARAM_DECIMALS, params::PARAM_DECIMALS);
        assert_eq!(PARAM_BASE, params::PARAM_BASE);
        assert_eq!(PARAM_PREFIX, params::PARAM_PREFIX);
        assert_eq!(PARAM_SUFFIX, params::PARAM_SUFFIX);
        assert_eq!(PARAM_NESTED_SELECTOR, params::PARAM_NESTED_SELECTOR);
        assert_eq!(PARAM_NESTED_CALLEE, params::PARAM_NESTED_CALLEE);
        assert_eq!(PARAM_FALLBACK_LABEL, params::PARAM_FALLBACK_LABEL);
        assert_eq!(PARAM_VISIBILITY, params::PARAM_VISIBILITY);
        assert_eq!(PARAM_CONST_VALUE, params::PARAM_CONST_VALUE);
        assert_eq!(PARAM_NESTED_STRUCT, params::PARAM_NESTED_STRUCT);
        assert_eq!(PARAM_NATIVE_CURRENCY, params::PARAM_NATIVE_CURRENCY);
        assert_eq!(PARAM_DYNAMIC_KIND, params::PARAM_DYNAMIC_KIND);
        assert_eq!(PARAM_NFT_COLLECTION, params::PARAM_NFT_COLLECTION);
        assert_eq!(PARAM_NFT_COLLECTION_PATH, params::PARAM_NFT_COLLECTION_PATH);
        assert_eq!(PARAM_INTERPOLATED_INTENT, params::PARAM_INTERPOLATED_INTENT);
        assert_eq!(PARAM_TERMINAL_KIND, params::PARAM_TERMINAL_KIND);
        assert_eq!(PARAM_INTEGER_WIDTH, params::PARAM_INTEGER_WIDTH);
        assert_eq!(PARAM_SENDER_ADDRESS, params::PARAM_SENDER_ADDRESS);
        assert_eq!(PARAM_WORD_GUARD, params::PARAM_WORD_GUARD);
        assert_eq!(PARAM_EXACT_EMPTY_BYTES, params::PARAM_EXACT_EMPTY_BYTES);
        assert_eq!(
            PARAM_EIP712_STRING_PREIMAGE,
            params::PARAM_EIP712_STRING_PREIMAGE
        );
        assert_eq!(MAX_SENDER_ADDRESSES, params::MAX_SENDER_ADDRESSES);
        assert_eq!(WORD_GUARD_PAYLOAD_LEN, params::WORD_GUARD_PAYLOAD_LEN);
        assert_eq!(WORD_GUARD_EQ, params::WORD_GUARD_EQ);
        assert_eq!(WORD_GUARD_NE, params::WORD_GUARD_NE);
        assert_eq!(
            INTERPOLATED_INTENT_VERSION,
            params::INTERPOLATED_INTENT_VERSION
        );

        // Visibility bytes.
        assert_eq!(VIS_ALWAYS, Visibility::Always as u8);
        assert_eq!(VIS_NEVER, Visibility::Never as u8);
        assert_eq!(VIS_OPTIONAL, Visibility::Optional as u8);
        assert_eq!(VIS_IF_NOT_IN, Visibility::IfNotIn as u8);
        assert_eq!(VIS_MUST_MATCH, Visibility::MustMatch as u8);
    }

    // ── VULN-erc7730-rule1-inert-field-nonaddr-action-hide (Rule 1) ──────

    #[test]
    fn rule1_inert_only_meta_tx_rejected() {
        // THE LIVE WITNESS: Rarible `MetaTransaction` renders `from`+`nonce`
        // (both inert) and hides `functionSignature` (the entire executed
        // action). Rule 1 must refuse — a reassuring banner over a blind-sign.
        let sig = "MetaTransaction(uint256 nonce, address from, bytes functionSignature)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"from","label":"User Address","format":"raw"},
              {"path":"nonce","label":"Meta Transaction Nonce","format":"raw"},
              {"path":"functionSignature","label":"Function Signature","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("inert-only clear-sign must be refused");
        assert!(
            err.contains("inert"),
            "rule-1 message names inert roles: {err}"
        );
    }

    #[test]
    fn rule1_shown_effect_address_ok() {
        // Celo `authorizeVoteSigner(address signer, ...)` shows `signer` — the
        // address being granted authority IS the effect. Must NOT be treated
        // as inert (the false-positive a naive inert list would trip).
        let sig = "authorizeVoteSigner(address signer, uint8 v, bytes32 r, bytes32 s)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"signer","label":"Signer","format":"addressName"},
              {"path":"v","label":"v","format":"raw"},
              {"path":"r","label":"r","format":"raw"},
              {"path":"s","label":"s","format":"raw"}
            ]"#,
        );
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok(),
            "a shown non-inert address (`signer`) satisfies rule 1"
        );
    }

    #[test]
    fn rule1_shown_amount_ok() {
        // A shown amount alongside a hidden inert `from` satisfies rule 1.
        let sig = "pay(address from, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"from","label":"From","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok());
    }

    #[test]
    fn completeness_flat_param_omitted_rejected() {
        // The canonical break: a `transfer` descriptor that shows only the
        // amount and never the recipient.
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[{"path":"amount","label":"Amount","format":"tokenAmount","params":{"token":"0x0000000000000000000000000000000000000000"}}]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("omitted recipient must be rejected");
        assert!(err.contains("`to`"), "error names the hidden param: {err}");
    }

    #[test]
    fn completeness_flat_all_covered_accepted() {
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn indexed_token_endpoints_do_not_cover_signed_address_array_route() {
        let sig = "swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"path.[0]"}},
              {"path":"amountOutMin","label":"Receive","format":"tokenAmount","params":{"tokenPath":"path.[-1]"}},
              {"path":"to","label":"To","format":"addressName"},
              {"path":"deadline","label":"Deadline","format":"date"}
            ]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("endpoint-only route must be incomplete");
        assert!(err.contains("indexed/sliced tokenPath"), "got: {err}");
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_err(),
            "two endpoint labels do not expose an entire address array"
        );
    }

    #[test]
    fn sliced_token_endpoints_do_not_cover_signed_packed_bytes_route() {
        let sig =
            "exactInput(bytes path,address recipient,uint256 amountIn,uint256 amountOutMinimum)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"path.[0:20]"}},
              {"path":"amountOutMinimum","label":"Receive","format":"tokenAmount","params":{"tokenPath":"path.[-20:]"}},
              {"path":"recipient","label":"To","format":"addressName"}
            ]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("endpoint-only packed route must be incomplete");
        assert!(err.contains("indexed/sliced tokenPath"), "got: {err}");
    }

    #[test]
    fn render_all_array_path_accounts_for_every_route_element() {
        let sig = "swap(uint256 amount,address[] path)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"path.[]","label":"Route","format":"addressName"}
            ]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok());
    }

    #[test]
    fn completeness_tuple_member_omitted_rejected() {
        // Uniswap exactInputSingle shape: every member but
        // `sqrtPriceLimitX96` is surfaced. Top-level granularity would call
        // the tuple "covered"; member granularity correctly rejects, because
        // the renderer can (and the attacker-set word would be) signed but
        // not shown.
        let sig = "swap((address tokenIn, address tokenOut, uint256 amountIn, uint160 sqrtPriceLimitX96) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}},
              {"path":"params.tokenOut","label":"To token","format":"addressName"}
            ]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("omitted tuple member must be rejected");
        assert!(
            err.contains("sqrtPriceLimitX96"),
            "error names the hidden member: {err}"
        );
    }

    #[test]
    fn completeness_tuple_member_hidden_via_never_accepted() {
        // Same shape, but the omitted member is an explicit `visible:"never"`
        // author decision — accepted (a conscious hide, what the lint forces).
        let sig = "swap((address tokenIn, address tokenOut, uint256 amountIn, uint160 sqrtPriceLimitX96) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}},
              {"path":"params.tokenOut","label":"To token","format":"addressName"},
              {"path":"params.sqrtPriceLimitX96","label":"Price limit","visible":"never"}
            ]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn completeness_tuple_all_members_covered_accepted() {
        // tokenIn covered via `tokenPath`, amountIn via its own field path.
        let sig = "swap((address tokenIn, uint256 amountIn) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[{"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}}]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn path_covers_tuple_member_matches_and_rejects() {
        assert!(path_covers_tuple_member(
            "params.amountIn",
            "params",
            "amountIn"
        ));
        assert!(path_covers_tuple_member(
            "#.params.amountIn",
            "params",
            "amountIn"
        ));
        assert!(path_covers_tuple_member(
            "params.order.x",
            "params",
            "order"
        )); // nested, one level
            // wrong member / wrong tuple / bare tuple / array hop / envelope root.
        assert!(!path_covers_tuple_member(
            "params.amountIn",
            "params",
            "tokenIn"
        ));
        assert!(!path_covers_tuple_member(
            "other.amountIn",
            "params",
            "amountIn"
        ));
        assert!(!path_covers_tuple_member("params", "params", "amountIn"));
        assert!(!path_covers_tuple_member("params[0]", "params", "amountIn"));
        assert!(!path_covers_tuple_member("@.value", "params", "amountIn"));
        assert!(!path_covers_tuple_member(
            "$.metadata",
            "params",
            "amountIn"
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // WYSIWYS visibility gate — VULN-erc7730-visible-never-noparam-clearsign.
    // Completeness (above) blesses `visible:"never"`; these guard that the
    // effect-bearing arguments are actually SHOWN.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn type_contains_address_is_token_exact() {
        assert!(type_contains_address("address"));
        assert!(type_contains_address("address[]"));
        assert!(type_contains_address("address[3]"));
        assert!(type_contains_address("(address,uint256)"));
        assert!(type_contains_address("(uint256,address)[]"));
        // No false positives on non-address ABI types.
        assert!(!type_contains_address("uint256"));
        assert!(!type_contains_address("bytes32"));
        assert!(!type_contains_address("bool"));
        assert!(!type_contains_address("string"));
        assert!(!type_contains_address("(uint256,bytes32)"));
    }

    #[test]
    fn visibility_all_hidden_rejected() {
        // The live witness: `setAllowedTarget` hides BOTH params → the device
        // would clear-sign banner + envelope + confirm with nothing shown.
        let sig = "setAllowedTarget(address target, bool allowed)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"target","label":"Target","visible":"never"},
              {"path":"allowed","label":"Allowed","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("all-hidden format must be refused");
        assert!(
            err.contains("surface at least one"),
            "rule-1 message: {err}"
        );
    }

    #[test]
    fn visibility_hidden_recipient_rejected() {
        // The canonical future-drain: recipient hidden, amount shown.
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName","visible":"never"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("hidden recipient must be refused");
        assert!(err.contains("`to`"), "names the hidden address: {err}");
    }

    #[test]
    fn visibility_all_shown_transfer_ok() {
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok());
    }

    #[test]
    fn visibility_zero_arg_ok() {
        let sig = "deposit()";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields("[]");
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok());
    }

    #[test]
    fn visibility_zero_arg_hidden_container_field_rejected() {
        // Zero calldata arguments do not bypass rule 3: hiding an envelope
        // value/metadata field would still be an explicit signed-and-unseen
        // presentation choice (native value is separately mandatory at runtime).
        let sig = "deposit()";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[{"path":"@.value","label":"Value","format":"raw","visible":"never"}]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("zero-argument formats must not bypass hidden-field rejection");
        assert!(
            err.contains("terminal type `<container>`"),
            "typed refusal: {err}"
        );
    }

    #[test]
    fn visibility_hidden_nonaddress_rejected() {
        // Even a scalar named `nonce` can be effect-bearing in an arbitrary
        // ABI. Type/name heuristics cannot make a signed-but-unseen word safe.
        let sig = "bump(address to, uint256 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"nonce","label":"Nonce","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("every hidden non-address operand must be refused");
        assert!(
            err.contains("terminal type `uint256`"),
            "typed refusal: {err}"
        );
    }

    #[test]
    fn visibility_hidden_dynamic_payload_rejected() {
        // Regression witness: pre-fix this produced a trusted `Execute` screen
        // showing only `target` while arbitrary nested action bytes stayed
        // signed and invisible.
        let sig = "execute(address target, bytes payload)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"target","label":"Target","format":"addressName"},
              {"path":"payload","label":"Payload","format":"raw","visible":"never"}
            ]"#,
        );
        check_contract_field_completeness(sig, &fmt, &parsed)
            .expect("the malicious descriptor explicitly accounts for both arguments");
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("hidden action payload must never clear-sign");
        assert!(
            err.contains("terminal type `bytes`"),
            "typed refusal: {err}"
        );
    }

    #[test]
    fn visibility_struct_named_address_cannot_bypass_hidden_material_gate() {
        // Malformed/hostile encodeType tail: a custom struct called `address`
        // must not inherit the exact-scalar-address exception and hide its
        // arbitrary payload hash behind a visible amount.
        let sig = "Order(address payload,uint256 amount)address(bytes action)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"payload","label":"Payload","format":"raw","visible":"never"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("a custom struct named address is not a scalar address");
        assert!(
            err.contains("terminal type `address`"),
            "typed refusal: {err}"
        );
    }

    #[test]
    fn visibility_tokenpath_surfaced_address_ok() {
        // Ondo pattern: the token address is hidden as its own field but is the
        // `tokenPath` of a SHOWN amount, so its identity reaches the user.
        let sig = "subscribe(address depositToken, uint256 depositAmount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"depositAmount","label":"Deposit","format":"tokenAmount","params":{"tokenPath":"depositToken"}},
              {"path":"depositToken","label":"Token","visible":"never"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_ok());
    }

    #[test]
    fn visibility_tuple_member_hidden_address_rejected() {
        // A static-tuple member the renderer addresses individually.
        let sig = "exec((address recipient, uint256 amount) order)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"order.recipient","label":"To","format":"addressName","visible":"never"},
              {"path":"order.amount","label":"Amount","format":"raw"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT)
            .expect_err("hidden tuple-member address must be refused");
        assert!(err.contains("order.recipient"), "names the member: {err}");
    }

    #[test]
    fn visibility_semantic_hidden_address_exemptions_are_unsupported() {
        // A signature/path-only exception would leak to any other deployment
        // sharing this ABI, so even a claimed router executor must be shown.
        let sig = "swap(address executor, address dstReceiver, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"executor","label":"Executor","visible":"never"},
              {"path":"dstReceiver","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT).is_err());
    }

    #[test]
    fn visibility_eip712_hidden_address_member_rejected() {
        // The typed-data analogue: a Permit `spender` set `visible:"never"`
        // signs an off-chain approval to an unseen address.
        let sig =
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"owner","label":"Owner","format":"addressName"},
              {"path":"spender","label":"Spender","format":"addressName","visible":"never"},
              {"path":"value","label":"Value","format":"raw"},
              {"path":"nonce","label":"Nonce","visible":"never"},
              {"path":"deadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("hidden typed-data spender must be refused");
        assert!(err.contains("spender"), "names the hidden member: {err}");
    }

    // ─────────────────────────────────────────────────────────────────────
    // EIP-712 nested-struct fund-routing address hide
    // (VULN-erc7730-eip712-nested-struct-address-hide). The visible:"never"
    // gate above only walked TOP-LEVEL members; an `address` nested inside a
    // struct member's opaque `hashStruct` word escaped it. These guard the
    // struct-def parse, the descent, and the on-device belt marker.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_struct_defs_from_encodetype_tail() {
        // Canonical two-level.
        let p =
            parse_format_key("Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)")
                .unwrap();
        assert_eq!(p.top_names, ["info", "amount"]);
        assert_eq!(p.top_types, ["Meta", "uint256"]);
        assert_eq!(
            p.struct_defs.get("Meta").expect("Meta parsed"),
            &vec![
                ("spender".to_string(), "address".to_string()),
                ("flags".to_string(), "uint256".to_string()),
            ]
        );

        // Real Uniswap Permit2 single.
        let p = parse_format_key(
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
        )
        .unwrap();
        assert_eq!(p.top_types[0], "PermitDetails");
        assert_eq!(
            p.struct_defs.get("PermitDetails").unwrap()[0],
            ("token".to_string(), "address".to_string())
        );

        // Forward-referenced structs (UniswapX ExclusiveDutchOrder — a member
        // whose struct type is defined LATER in the tail; canonical EIP-712
        // sorts struct defs, so forward refs are the norm).
        let p = parse_format_key(
            "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,\
             uint256 deadline,ExclusiveDutchOrder witness)DutchOutput(address token,\
             uint256 startAmount,uint256 endAmount,address recipient)ExclusiveDutchOrder(\
             OrderInfo info,uint256 decayStartTime,uint256 decayEndTime,address exclusiveFiller,\
             uint256 exclusivityOverrideBps,address inputToken,uint256 inputStartAmount,\
             uint256 inputEndAmount,DutchOutput[] outputs)OrderInfo(address reactor,address swapper,\
             uint256 nonce,uint256 deadline,address additionalValidationContract,\
             bytes additionalValidationData)TokenPermissions(address token,uint256 amount)",
        )
        .unwrap();
        for s in [
            "ExclusiveDutchOrder",
            "OrderInfo",
            "DutchOutput",
            "TokenPermissions",
        ] {
            assert!(p.struct_defs.contains_key(s), "parsed {s}");
        }
        let edo = p.struct_defs.get("ExclusiveDutchOrder").unwrap();
        assert!(edo
            .iter()
            .any(|(n, t)| n == "outputs" && t == "DutchOutput[]"));
    }

    #[test]
    fn parse_struct_defs_rejects_duplicate_member_names_for_every_member_shape() {
        let cases = [
            (
                "primitive",
                "Root(Primitive value)Primitive(uint256 amount,uint256 amount)",
                "Primitive",
                "amount",
            ),
            (
                "address",
                "Root(AddressBook book)AddressBook(address recipient,address recipient)",
                "AddressBook",
                "recipient",
            ),
            (
                "array",
                "Root(Batch batch)Batch(uint256[] values,uint256[] values)",
                "Batch",
                "values",
            ),
            (
                "transitively referenced nested struct",
                "Root(Outer outer)Inner(bytes32 salt,bytes32 salt)Outer(Inner leg)",
                "Inner",
                "salt",
            ),
        ];

        for (shape, encode_type, struct_name, member_name) in cases {
            let err = parse_format_key(encode_type)
                .err()
                .unwrap_or_else(|| panic!("duplicate {shape} member must be refused"));
            assert!(
                err.contains(&format!("struct `{struct_name}`")),
                "{shape} error must name its struct: {err}"
            );
            assert!(
                err.contains(&format!("member name `{member_name}`")),
                "{shape} error must name its duplicate member: {err}"
            );
        }
    }

    #[test]
    fn parse_struct_defs_accepts_distinct_nested_and_array_members() {
        let parsed = parse_format_key(
            "Root(Outer outer)Inner(address recipient,uint256 amount)\
             Outer(Inner first,Inner second,Inner[] many)",
        )
        .expect("distinct referenced-struct member names must remain accepted");

        assert_eq!(
            parsed.struct_defs["Inner"],
            [
                ("recipient".to_string(), "address".to_string()),
                ("amount".to_string(), "uint256".to_string()),
            ]
        );
        assert_eq!(
            parsed.struct_defs["Outer"],
            [
                ("first".to_string(), "Inner".to_string()),
                ("second".to_string(), "Inner".to_string()),
                ("many".to_string(), "Inner[]".to_string()),
            ]
        );
    }

    #[test]
    fn eip712_nested_type_hash_matches_foundry() {
        // v1 targets — foundry `cast keccak` of the exact `encodeType`.
        let p = parse_format_key(
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
        )
        .unwrap();
        assert_eq!(
            hex::encode(eip712_nested_type_hash("PermitDetails", &p.struct_defs).unwrap()),
            "65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678",
        );
        assert_eq!(
            eip712_member_count("PermitDetails", &p.struct_defs).unwrap(),
            4
        );

        let p2 = parse_format_key(
            "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,\
             uint256 deadline)TokenPermissions(address token,uint256 amount)",
        )
        .unwrap();
        assert_eq!(
            hex::encode(eip712_nested_type_hash("TokenPermissions", &p2.struct_defs).unwrap()),
            "618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1",
        );

        // Transitive + alphabetical sort + dedup (de-risks v2). encodeType(A) =
        // def(A) ‖ sorted[def(B), def(C)].
        let mut defs: StructDefs = BTreeMap::new();
        defs.insert(
            "A".into(),
            vec![("b".into(), "B".into()), ("x".into(), "address".into())],
        );
        defs.insert(
            "B".into(),
            vec![("y".into(), "address".into()), ("c".into(), "C".into())],
        );
        defs.insert("C".into(), vec![("z".into(), "uint256".into())]);
        assert_eq!(
            eip712_encode_type("A", &defs).unwrap(),
            "A(B b,address x)B(address y,C c)C(uint256 z)",
        );
        assert_eq!(
            hex::encode(eip712_nested_type_hash("A", &defs).unwrap()),
            "a8b08b15aeb75ef0b731673e33d2e8b4523c703d6ecebbbd56975cd9af217ad4",
        );

        // Address-word predicate (E2 bitmap source): only a bare `address`
        // member's own word is an address; a struct member is a hashStruct word.
        assert!(eip712_member_word_is_address("address"));
        assert!(!eip712_member_word_is_address("uint160"));
        assert!(!eip712_member_word_is_address("PermitDetails"));
    }

    #[test]
    fn visibility_eip712_nested_hidden_address_rejected() {
        // THE canonical exploit: a benign `amount` renders while `info` (a
        // Meta struct hiding `spender`) is `visible:"never"`. Pre-fix the
        // gate blessed it (Meta is not the `address` token); post-fix the
        // descent reaches `info.spender`.
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("hidden nested spender must be refused");
        assert!(
            err.contains("info.spender"),
            "names the nested member: {err}"
        );
    }

    #[test]
    fn visibility_eip712_nested_address_shown_accepted() {
        // Same shape, but `info.spender` is surfaced by a visible field →
        // no hidden fund-routing address, gate passes.
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info.spender","label":"Spender","format":"addressName"}
            ]"#,
        );
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_EIP712).is_ok(),
            "shown nested address should pass"
        );
    }

    #[test]
    fn visibility_eip712_permit_single_hidden_token_rejected() {
        // Real Uniswap Permit2: hiding `details` hides `details.token`, the
        // token being approved — a nested fund-routing address.
        let sig = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"details","label":"Details","visible":"never"},
              {"path":"sigDeadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("hidden Permit2 token must be refused");
        assert!(err.contains("details.token"), "names nested token: {err}");
    }

    #[test]
    fn visibility_eip712_nested_no_address_still_rejected_when_hidden() {
        // A hashStruct without an address can still encode arbitrary
        // effect-bearing semantics. Hiding the whole struct is not safe.
        let sig = "Order(Meta info,uint256 amount)Meta(uint256 a,uint256 b)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("hidden non-address struct must be refused");
        assert!(err.contains("terminal type `Meta`"), "typed refusal: {err}");
    }

    #[test]
    fn visibility_eip712_array_of_struct_address_rejected() {
        // `details` is `PermitDetails[]` — array-of-struct with a nested
        // `token` address. Elements aren't individually addressable on
        // device, so a nested address can't be shown → refuse.
        let sig = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"details","label":"Details","visible":"never"},
              {"path":"sigDeadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect_err("array-of-struct nested address must be refused");
        assert!(err.contains("details"), "names the array member: {err}");
    }

    #[test]
    fn visibility_eip712_nested_address_has_no_semantic_exemption() {
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_EIP712).is_err());
    }

    #[test]
    fn nested_struct_marker_emitted_on_first_field() {
        // A nested-struct EIP-712 format that PASSES the gate (no nested
        // address) is pinned with the PARAM_NESTED_STRUCT belt on field[0].
        let sig = "Order(Meta info,uint256 amount)Meta(uint256 a,uint256 b)";
        let parsed = parse_format_key(sig).unwrap();
        let field0: FieldDef =
            serde_json::from_str(r#"{"path":"amount","label":"Amount","format":"raw"}"#).unwrap();
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            eip712_word_guard_source_required: false,
        };
        let mut pool = Pool::new();
        let cf = compile_one_field(
            sig,
            0,
            &field0,
            CTX_EIP712,
            &parsed,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            true,
        )
        .unwrap();
        let bytes = pool.into_bytes();
        let off = cf.param_off as usize;
        assert!(off != 0, "marker forces a non-empty param blob");
        let len = bytes[off] as usize;
        let blob = &bytes[off + 1..off + 1 + len];
        // Walk the TLV blob and assert PARAM_NESTED_STRUCT (0x41 / [0x01]).
        let mut found = false;
        let mut c = 0;
        while c + 2 <= blob.len() {
            let tag = blob[c];
            let l = blob[c + 1] as usize;
            if tag == PARAM_NESTED_STRUCT {
                assert_eq!(&blob[c + 2..c + 2 + l], &[0x01]);
                found = true;
            }
            c += 2 + l;
        }
        assert!(found, "PARAM_NESTED_STRUCT emitted on field[0]");
    }

    #[test]
    fn nested_struct_marker_not_emitted_without_nested_struct() {
        // A struct-free EIP-712 primary type gets no marker (has_nested_struct
        // is false → the belt only fires for genuinely un-expandable types).
        let sig = "Permit(address owner,address spender,uint256 value)";
        let parsed = parse_format_key(sig).unwrap();
        assert!(parsed.struct_defs.is_empty());
        let has_nested = parsed.top_types.iter().any(|ty| {
            let (base, _) = split_array_suffix(ty);
            type_is_struct(base, &parsed)
        });
        assert!(!has_nested, "no nested struct → no marker");
    }

    #[test]
    fn path_matches_member_exact() {
        assert!(path_matches_member("info.spender", "info.spender"));
        assert!(path_matches_member("#.info.spender", "info.spender"));
        assert!(path_matches_member(
            "witness.info.reactor",
            "witness.info.reactor"
        ));
        // Parent alone does NOT cover a nested member.
        assert!(!path_matches_member("info", "info.spender"));
        // A deeper path is not the member.
        assert!(!path_matches_member("info.spender.x", "info.spender"));
        // Array hop / envelope roots never match a scalar member.
        assert!(!path_matches_member(
            "info.outputs[0].recipient",
            "info.outputs.recipient"
        ));
        assert!(!path_matches_member("@.value", "info.spender"));
        assert!(!path_matches_member("$.x", "info.spender"));
    }

    #[test]
    fn visibility_gate_runs_inside_compile_one_format() {
        // Integration: the witness format is refused by the full compile path,
        // not just the standalone checker — so the tolerant corpus drops it to
        // blind-sign and it can never ship as a trusted clear-sign.
        let sig = "setAllowedTarget(address target, bool allowed)";
        let fmt = fmt_from_fields(
            r#"[
              {"path":"target","label":"Target","visible":"never"},
              {"path":"allowed","label":"Allowed","visible":"never"}
            ]"#,
        );
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            eip712_word_guard_source_required: false,
        };
        let mut pool = Pool::new();
        let mut out = Vec::new();
        let res = compile_one_format(
            sig,
            &fmt,
            CTX_CONTRACT,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        );
        assert!(
            res.is_err(),
            "compile_one_format must refuse the all-hidden witness"
        );
    }

    // Audit 2026-06-25 HIGH-1 — EIP-712 completeness lint regression guards.

    /// Build an in-memory `Format` from a list of field paths.
    fn fmt_with_paths(paths: &[&str]) -> Format {
        let fields: Vec<serde_json::Value> = paths
            .iter()
            .map(|p| serde_json::json!({ "path": p, "format": "raw" }))
            .collect();
        serde_json::from_value(serde_json::json!({ "fields": fields }))
            .expect("synthetic format deserializes")
    }

    const PERMIT2_KEY: &str =
        "PermitTransferFrom(address token,address spender,uint256 amount,uint256 nonce,uint256 deadline)";

    #[test]
    fn eip712_completeness_rejects_omitted_member() {
        // Renders only `token` + `amount`; `spender`/`nonce`/`deadline`
        // are signed (folded into structHash) but never shown — the exact
        // HIGH-1 Permit2 drain shape. The lint must refuse to pin it.
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fmt = fmt_with_paths(&["token", "amount"]);
        let err = check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed)
            .expect_err("incomplete EIP-712 descriptor must be rejected");
        assert!(
            err.contains("spender"),
            "error should name the first omitted member: {err}"
        );
    }

    #[test]
    fn eip712_completeness_rejects_omitted_nested_scalar_member() {
        let sig = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
                   PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_with_paths(&["details.token", "spender", "sigDeadline"]);
        let err = check_eip712_nested_field_completeness(sig, &fmt, &parsed)
            .expect_err("one visible child must not cover omitted nested signed scalars");
        assert!(
            err.contains("details.amount"),
            "refusal should name the first omitted nested member: {err}"
        );
    }

    #[test]
    fn eip712_completeness_rejects_omitted_array_element_member() {
        let sig = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
                   PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_with_paths(&["details.[].token", "spender", "sigDeadline"]);
        let err = check_eip712_nested_field_completeness(sig, &fmt, &parsed)
            .expect_err("one element child must not cover omitted members in every array element");
        assert!(
            err.contains("details.[].amount"),
            "refusal should name the first omitted per-element member: {err}"
        );
    }

    #[test]
    fn eip712_nested_completeness_accepts_exact_full_coverage_and_token_path() {
        let sig = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
                   PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"details.amount","label":"Amount","format":"tokenAmount",
               "params":{"tokenPath":"details.token"}},
              {"path":"details.expiration","label":"Expiration","format":"date"},
              {"path":"details.nonce","label":"Nonce","format":"raw"},
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"sigDeadline","label":"Deadline","format":"date"}
            ]"#,
        );
        check_eip712_field_completeness(sig, &fmt, &parsed).unwrap();
        check_field_visibility(sig, &fmt, &parsed, CTX_EIP712).unwrap();
        check_eip712_nested_field_completeness(sig, &fmt, &parsed).unwrap();

        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect("full nested coverage must still emit a clear-sign format");
    }

    #[test]
    fn eip712_nested_array_completeness_accepts_full_element_coverage() {
        let sig = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
                   PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"details.[].amount","label":"Amount","format":"tokenAmount",
               "params":{"tokenPath":"details.[].token"}},
              {"path":"details.[].expiration","label":"Expiration","format":"date"},
              {"path":"details.[].nonce","label":"Nonce","format":"raw"},
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"sigDeadline","label":"Deadline","format":"date"}
            ]"#,
        );
        check_eip712_nested_field_completeness(sig, &fmt, &parsed)
            .expect("every member of every rendered array element is covered");
    }

    #[test]
    fn eip712_multidimensional_struct_array_emits_only_bare_refusal() {
        let sig = "Batch(Item[][] items,address spender)Item(address token,uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"items.[].amount","label":"Amount","format":"tokenAmount",
               "params":{"tokenPath":"items.[].token"},"visible":"always"},
              {"path":"spender","label":"Spender","format":"addressName","visible":"always"}
            ]"#,
        );
        check_field_visibility(sig, &fmt, &parsed, CTX_EIP712)
            .expect("the regression isolates array rank, not visibility");
        let err = check_eip712_nested_field_completeness(sig, &fmt, &parsed)
            .expect_err("one wildcard must not account for a two-dimensional signed array");
        assert!(err.contains("more than one array dimension"), "{err}");
        let bare_parent = fmt_from_fields(
            r#"[
              {"path":"items","label":"Items","visible":"never"},
              {"path":"spender","label":"Spender","format":"addressName","visible":"always"}
            ]"#,
        );
        let err = check_eip712_nested_field_completeness(sig, &bare_parent, &parsed)
            .expect_err("a bare-parent field must not bypass signed array-rank admission");
        assert!(err.contains("more than one array dimension"), "{err}");

        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        assert!(
            try_compile_eip712_nested(
                sig,
                &fmt,
                &parsed,
                &mut ctx,
                &mut pool,
                &BTreeMap::new(),
                None,
            )
            .expect("unsupported rank must fail closed, not error in the emitter")
            .is_none(),
            "the independent emitter backstop must not produce an active v0x03 anchor"
        );

        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect("unsupported rank must lower only to canonical device-refusal IR");

        assert_eq!(out[4], 1, "refusal format has one canonical carrier field");
        assert_eq!(out[8], 0, "bare refusal carries no active nested descent");
        assert_eq!(out[9], 0, "bare refusal carries no string preimages");
        let field = 10 + out[5] as usize + 32;
        assert_eq!(out[field], FMT_RAW);
        let label_len = out[field + 1] as usize;
        assert_eq!(&out[field + 2..field + 2 + label_len], b"Unsupported");
        let offsets = field + 2 + label_len;
        assert_eq!(u16::from_be_bytes([out[offsets], out[offsets + 1]]), 0);
        let param_off = u16::from_be_bytes([out[offsets + 2], out[offsets + 3]]) as usize;
        assert_ne!(param_off, 0);

        let pool = pool.into_bytes();
        let blob_len = pool[param_off] as usize;
        let blob = &pool[param_off + 1..param_off + 1 + blob_len];
        let mut cursor = 0;
        let mut bare_marker = false;
        let mut active_anchor = false;
        while cursor + 2 <= blob.len() {
            let tag = blob[cursor];
            let len = blob[cursor + 1] as usize;
            let payload = &blob[cursor + 2..cursor + 2 + len];
            if tag == PARAM_NESTED_STRUCT {
                bare_marker |= payload == [0x01];
                active_anchor |= payload.first() == Some(&0x03);
            }
            cursor += 2 + len;
        }
        assert_eq!(cursor, blob.len());
        assert!(
            bare_marker,
            "rank refusal must carry the device belt marker"
        );
        assert!(
            !active_anchor,
            "rank refusal must never carry an active v0x03 anchor"
        );
    }

    #[test]
    fn nested_token_path_rejects_array_hash_and_primitive_named_struct() {
        let sig = "Order(Outer outer)Outer(uint256 amount,address[] tokens)address(bytes32 salt)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"outer.amount","label":"Amount","format":"tokenAmount",
               "params":{"tokenPath":"outer.tokens"},"visible":"always"},
              {"path":"outer.tokens.[].salt","label":"Salt","format":"raw",
               "visible":"always"}
            ]"#,
        );
        check_eip712_field_completeness(sig, &fmt, &parsed).unwrap();
        check_field_visibility(sig, &fmt, &parsed, CTX_EIP712).unwrap();
        check_eip712_nested_field_completeness(sig, &fmt, &parsed).unwrap();

        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        assert!(
            try_compile_eip712_nested(
                sig,
                &fmt,
                &parsed,
                &mut ctx,
                &mut pool,
                &BTreeMap::new(),
                None,
            )
            .expect("the nested emitter must fail closed without a build error")
            .is_none(),
            "an array hashStruct word must never lower as a token address"
        );
        assert!(
            compile_token_path("outer.tokens", CTX_EIP712, &parsed).is_err(),
            "the shared flat tokenPath compiler must reject the same ambiguous endpoint"
        );
    }

    #[test]
    fn eip712_nested_completeness_rejects_deep_leaf_omission() {
        let sig = "Order(Outer outer)Inner(uint256 amount,uint256 nonce)\
                   Outer(Inner inner,uint256 salt)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_with_paths(&["outer.inner.nonce", "outer.salt"]);
        let err = check_eip712_nested_field_completeness(sig, &fmt, &parsed)
            .expect_err("a sibling must not cover a missing transitive leaf");
        assert!(err.contains("outer.inner.amount"), "{err}");
    }

    #[test]
    fn eip712_incomplete_nested_format_is_rejected_end_to_end() {
        let sig = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
                   PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let fmt = fmt_from_fields(
            r#"[
              {"path":"details.token","label":"Token","format":"addressName"},
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"sigDeadline","label":"Deadline","format":"date"}
            ]"#,
        );
        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let mut out = Vec::new();
        let err = compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect_err("a partial nested format must never emit an authenticated anchor");
        assert!(err.contains("details.amount"), "{err}");
        assert!(out.is_empty(), "no format bytes may be emitted on refusal");
    }

    #[test]
    fn eip712_completeness_accepts_full_coverage() {
        // Every member has a field — passes (mirrors the shipped
        // circle-usdc-{rwa,twa} authorization descriptors).
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fmt = fmt_with_paths(&["token", "spender", "amount", "nonce", "deadline"]);
        assert!(check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed).is_ok());
    }

    #[test]
    fn eip712_completeness_accepts_tokenpath_coverage() {
        // A member surfaced only as another field's `tokenPath` counts as
        // covered (parity with the contract lint): here `token` rides on
        // the `amount` field's tokenPath, and the rest have their own
        // fields. `spender`/`nonce`/`deadline` still need fields.
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fields = serde_json::json!({
            "fields": [
                { "path": "amount", "format": "tokenAmount", "params": { "tokenPath": "token" } },
                { "path": "spender", "format": "addressName" },
                { "path": "nonce", "format": "raw", "visible": "never" },
                { "path": "deadline", "format": "raw" },
            ]
        });
        let fmt: Format = serde_json::from_value(fields).unwrap();
        assert!(check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed).is_ok());
    }

    #[test]
    fn tokenpath_coverage_requires_a_visible_consuming_formatter() {
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let invalid_fields = [
            // `raw` ignores tokenPath and therefore cannot display identity.
            serde_json::json!([
                { "path": "amount", "format": "raw", "params": { "tokenPath": "token" } },
                { "path": "spender", "format": "addressName" },
                { "path": "nonce", "format": "raw" },
                { "path": "deadline", "format": "raw" }
            ]),
            // A hidden amount paints no token identity.
            serde_json::json!([
                { "path": "amount", "format": "tokenAmount", "params": { "tokenPath": "token" }, "visible": "never" },
                { "path": "spender", "format": "addressName" },
                { "path": "nonce", "format": "raw" },
                { "path": "deadline", "format": "raw" }
            ]),
            // tokenAmount over an address terminal is an inadmissible type pair.
            serde_json::json!([
                { "path": "spender", "format": "tokenAmount", "params": { "tokenPath": "token" } },
                { "path": "amount", "format": "raw" },
                { "path": "nonce", "format": "raw" },
                { "path": "deadline", "format": "raw" }
            ]),
        ];
        for fields in invalid_fields {
            let fmt: Format = serde_json::from_value(serde_json::json!({ "fields": fields }))
                .expect("synthetic format");
            let error = check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed)
                .expect_err("ignored/hidden/inapplicable tokenPath must not cover token");
            assert!(error.contains("`token`"), "unexpected refusal: {error}");
        }
    }

    fn test_ctx() -> CompileCtx {
        CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            eip712_word_guard_source_required: false,
        }
    }

    fn nested_calldata_format() -> Format {
        serde_json::from_value(serde_json::json!({
            "intent": "Forward call",
            "fields": [
                {
                    "path": "target",
                    "label": "Target",
                    "format": "addressName",
                    "visible": "always"
                },
                {
                    "path": "data",
                    "label": "Call",
                    "format": "calldata",
                    "params": { "calleePath": "target" },
                    "visible": "always"
                }
            ]
        }))
        .expect("synthetic nested-calldata format")
    }

    fn compile_nested_calldata_fixture(
        format: &Format,
        enrollments: &[NestedCalldataEnrollment],
    ) -> Result<(Pool, Vec<u8>, CompileCtx), String> {
        use pqsigner_erc7730::render::calldata_policy::{
            TEST_NESTED_CALLDATA_DESCRIPTOR_HASH, TEST_NESTED_CALLDATA_PARENT_CONTRACT,
        };

        let capabilities = Erc20Capabilities::default();
        let deployment = InterpolationDeployment {
            chain_id: 31_337,
            contract: TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            erc20_capabilities: &capabilities,
        };
        let mut ctx = test_ctx();
        ctx.descriptor_hash = TEST_NESTED_CALLDATA_DESCRIPTOR_HASH;
        let mut pool = Pool::new();
        let mut formats = vec![1];
        compile_one_format_with_nested_calldata_enrollments(
            "forward(address target,bytes data)",
            format,
            CTX_CONTRACT,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut formats,
            Some(&deployment),
            enrollments,
        )?;
        Ok((pool, formats, ctx))
    }

    #[test]
    fn enrolled_nested_calldata_compiles_only_fixed_semantics() {
        use pqsigner_erc7730::{
            ir::ContextKind,
            render::{
                calldata_policy::{
                    TEST_NESTED_CALLDATA_CALLEE_PATH, TEST_NESTED_CALLDATA_ENROLLMENTS,
                    TEST_NESTED_CALLDATA_FIELD_PATH, TEST_NESTED_CALLDATA_PARENT_CONTRACT,
                },
                params::{self, DYNAMIC_KIND_BYTES},
            },
        };

        let (pool, formats, ctx) = compile_nested_calldata_fixture(
            &nested_calldata_format(),
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .expect("exact test-only enrollment compiles");
        let ir = Erc7730Ir {
            schema_ver: SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 31_337,
            contract: TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            descriptor_hash: ctx.descriptor_hash,
            domain_separator: [0; 32],
            owner: b"",
            contract_name: b"",
            pool: &pool.buf,
            formats: &formats,
            raw: &[],
        };
        let header = ir
            .format_iter()
            .next()
            .expect("one format")
            .expect("canonical compiled format");
        assert_eq!(header.selector, [0x6f, 0xad, 0xcf, 0x72]);
        assert_eq!(header.static_head_words, 2);
        let fields: Vec<_> = header
            .fields()
            .map(|field| field.expect("canonical field"))
            .collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].format_op, FMT_CALLDATA);
        assert_eq!(
            ir.path_bytes(fields[1].path_off).unwrap(),
            TEST_NESTED_CALLDATA_FIELD_PATH
        );
        let nested = params::parse(&ir, fields[1].param_off).expect("nested params");
        assert_eq!(
            nested.nested_callee,
            Some(&TEST_NESTED_CALLDATA_CALLEE_PATH)
        );
        assert_eq!(nested.nested_selector, None);
        assert_eq!(nested.dynamic_kind, Some(DYNAMIC_KIND_BYTES));
        assert_eq!(nested.terminal_kind, Some(TerminalKind::DynamicBytes));

        let bytes = build_ir(
            CTX_CONTRACT,
            31_337,
            TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            &[0; 32],
            &ctx,
            &pool.buf,
            &formats,
        )
        .expect("synthetic IR");
        #[cfg(feature = "nested-calldata-test-fixture")]
        assert!(Erc7730Ir::parse(&bytes).is_ok());
        #[cfg(not(feature = "nested-calldata-test-fixture"))]
        assert!(Erc7730Ir::parse(&bytes).is_err());
    }

    #[test]
    fn nested_calldata_compiler_refuses_missing_or_drifted_authority() {
        use pqsigner_erc7730::render::calldata_policy::{
            TEST_NESTED_CALLDATA_ENROLLMENT, TEST_NESTED_CALLDATA_ENROLLMENTS,
        };

        let error = compile_nested_calldata_fixture(&nested_calldata_format(), &[])
            .err()
            .expect("production's empty enrollment table must refuse");
        assert!(error.contains("requires exactly one matching"), "{error}");

        let mut drifted = TEST_NESTED_CALLDATA_ENROLLMENT;
        drifted.canonical_signature = "forward(uint256,bytes)";
        let error = compile_nested_calldata_fixture(&nested_calldata_format(), &[drifted])
            .err()
            .expect("canonical signature drift must refuse");
        assert!(error.contains("signature/selector drift"), "{error}");

        let mut missing_callee = nested_calldata_format();
        missing_callee.fields[1].params = None;
        let error =
            compile_nested_calldata_fixture(&missing_callee, TEST_NESTED_CALLDATA_ENROLLMENTS)
                .err()
                .expect("calleePath is mandatory");
        assert!(error.contains("requires calldata params"), "{error}");

        for forbidden in [
            "selector",
            "selectorPath",
            "amountPath",
            "spenderPath",
            "chainIdPath",
            "valuePath",
            "delegateCall",
        ] {
            let mut extra_semantics = nested_calldata_format();
            let mut params = serde_json::Map::new();
            params.insert(
                "calleePath".to_string(),
                serde_json::Value::String("target".to_string()),
            );
            params.insert(
                forbidden.to_string(),
                serde_json::Value::String("unsupported".to_string()),
            );
            extra_semantics.fields[1].params = Some(serde_json::Value::Object(params));
            let error =
                compile_nested_calldata_fixture(&extra_semantics, TEST_NESTED_CALLDATA_ENROLLMENTS)
                    .err()
                    .unwrap_or_else(|| panic!("nested semantic `{forbidden}` is outside N2"));
            assert!(error.contains("only mandatory calleePath"), "{error}");
        }

        let mut optional = nested_calldata_format();
        optional.fields[1].visible = Some("optional".to_string());
        let error = compile_nested_calldata_fixture(&optional, TEST_NESTED_CALLDATA_ENROLLMENTS)
            .err()
            .expect("calldata must be always visible");
        assert!(error.contains("always-visible calldata"), "{error}");

        let mut wrong_ordinal = nested_calldata_format();
        wrong_ordinal.fields.swap(0, 1);
        let error =
            compile_nested_calldata_fixture(&wrong_ordinal, TEST_NESTED_CALLDATA_ENROLLMENTS)
                .err()
                .expect("field ordinal is policy-bound");
        assert!(
            error.contains("field[1]") || error.contains("path differs"),
            "{error}"
        );
    }

    #[test]
    fn nested_callee_path_compiler_accepts_only_direct_address_authority() {
        let parsed = parse_format_key("forward(address target,bytes data)").unwrap();
        assert_eq!(
            compile_callee_address_path("target", CTX_CONTRACT, &parsed).unwrap(),
            [PATHOP_ROOT_STRUCT, PATHOP_FIELD_IDX, 0, 0]
        );
        assert_eq!(
            compile_callee_address_path("@.to", CTX_CONTRACT, &parsed).unwrap(),
            NFT_COLLECTION_TO_PATH
        );
        for rejected in ["data", "@.from", "@.value"] {
            assert!(
                compile_callee_address_path(rejected, CTX_CONTRACT, &parsed).is_err(),
                "accepted non-address callee {rejected}"
            );
        }

        let array = parse_format_key("forwardMany(address[] targets,bytes data)").unwrap();
        assert!(compile_callee_address_path("targets", CTX_CONTRACT, &array).is_err());
        let tuple = parse_format_key("forwardTuple((address target,uint256 mode) call,bytes data)")
            .unwrap();
        assert!(compile_callee_address_path("call.target", CTX_CONTRACT, &tuple).is_err());
    }

    fn router02_format(exact_input: bool) -> (&'static str, Format) {
        let (signature, first_path, first_label, second_path, second_label) = if exact_input {
            (
                "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
                "params.amountIn",
                "Send",
                "params.amountOutMinimum",
                "Minimum to Receive",
            )
        } else {
            (
                "exactOutputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountOut,uint256 amountInMaximum,uint160 sqrtPriceLimitX96) params)",
                "params.amountInMaximum",
                "Maximum Amount In",
                "params.amountOut",
                "Amount to Receive",
            )
        };
        let format = serde_json::from_value(serde_json::json!({
            "intent": "Swap",
            "fields": [
                {
                    "path": first_path,
                    "label": first_label,
                    "format": "tokenAmount",
                    "params": { "tokenPath": "params.tokenIn" },
                    "visible": "always"
                },
                {
                    "path": second_path,
                    "label": second_label,
                    "format": "tokenAmount",
                    "params": { "tokenPath": "params.tokenOut" },
                    "visible": "always"
                },
                {
                    "path": "params.fee",
                    "label": "Uniswap fee",
                    "format": "unit",
                    "params": { "decimals": 4, "base": "%", "prefix": false },
                    "visible": "always"
                },
                {
                    "path": "params.recipient",
                    "label": "Beneficiary",
                    "format": "addressName",
                    "params": {
                        "types": ["eoa", "contract"],
                        "sources": ["local", "ens"],
                        "senderAddress": ["0x0000000000000000000000000000000000000001"]
                    },
                    "visible": "always"
                },
                {
                    "path": "params.sqrtPriceLimitX96",
                    "label": "Price limit",
                    "format": "raw",
                    "visible": "always"
                },
                {
                    "path": "@.value",
                    "label": "Native value",
                    "format": "raw",
                    "visible": "always"
                }
            ]
        }))
        .expect("valid Router02 test format");
        (signature, format)
    }

    fn router02_packed_format(exact_input: bool) -> (&'static str, Format) {
        let (
            signature,
            amount_in_path,
            amount_in_label,
            amount_out_path,
            amount_out_label,
            token_in_path,
            token_out_path,
        ) = if exact_input {
            (
                "exactInput((bytes path,address recipient,uint256 amountIn,uint256 amountOutMinimum) params)",
                "params.amountIn",
                "Swap input",
                "params.amountOutMinimum",
                "Minimum to Receive",
                "params.path.[0:20]",
                "params.path.[-20:]",
            )
        } else {
            (
                "exactOutput((bytes path,address recipient,uint256 amountOut,uint256 amountInMaximum) params)",
                "params.amountInMaximum",
                "Max swap input",
                "params.amountOut",
                "Amount to Receive",
                "params.path.[-20:]",
                "params.path.[0:20]",
            )
        };
        let format = serde_json::from_value(serde_json::json!({
            "intent": "Swap",
            "fields": [
                {
                    "path": "@.value", "label": "Native value", "format": "amount",
                    "visible": "always"
                },
                {
                    "path": amount_in_path, "label": amount_in_label, "format": "tokenAmount",
                    "params": { "tokenPath": token_in_path }, "visible": "always"
                },
                {
                    "path": amount_out_path, "label": amount_out_label, "format": "tokenAmount",
                    "params": { "tokenPath": token_out_path }, "visible": "always"
                },
                {
                    "path": "params.path", "label": "Route", "format": "uniswapV3Path",
                    "visible": "always"
                },
                {
                    "path": "params.recipient", "label": "Beneficiary", "format": "addressName",
                    "params": {
                        "types": ["eoa", "contract"], "sources": ["local", "ens"],
                        "senderAddress": ["0x0000000000000000000000000000000000000001"]
                    },
                    "visible": "always"
                }
            ]
        }))
        .expect("valid packed Router02 test format");
        (signature, format)
    }

    fn compile_router02_packed_test_format(
        exact_input: bool,
        ctx: &mut CompileCtx,
        deployment: &InterpolationDeployment<'_>,
    ) -> Result<(Pool, Vec<u8>, Vec<u16>), String> {
        let (sig, fmt) = router02_packed_format(exact_input);
        let mut pool = Pool::new();
        let mut format = Vec::new();
        compile_one_format(
            sig,
            &fmt,
            CTX_CONTRACT,
            ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut format,
            Some(deployment),
        )?;
        let offsets = contract_format_param_offsets(&format);
        Ok((pool, format, offsets))
    }

    fn contract_format_param_offsets(format: &[u8]) -> Vec<u16> {
        assert!(format.len() >= 10, "contract format header");
        let field_count = format[4] as usize;
        let intent_len = format[5] as usize;
        assert_eq!(format[9], 0, "contract formats carry no string preimages");
        let mut cursor = 10 + intent_len;
        let mut offsets = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let label_len = format[cursor + 1] as usize;
            let offsets_at = cursor + 2 + label_len;
            offsets.push(u16::from_be_bytes([
                format[offsets_at + 2],
                format[offsets_at + 3],
            ]));
            cursor = offsets_at + 4;
        }
        assert_eq!(cursor, format.len(), "consume exact contract format bytes");
        offsets
    }

    fn compile_router02_test_format(
        exact_input: bool,
        ctx: &mut CompileCtx,
        deployment: &InterpolationDeployment<'_>,
    ) -> Result<(Pool, Vec<u8>, Vec<u16>), String> {
        let (sig, fmt) = router02_format(exact_input);
        let mut pool = Pool::new();
        let mut format = Vec::new();
        compile_one_format(
            sig,
            &fmt,
            CTX_CONTRACT,
            ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut format,
            Some(deployment),
        )?;
        let offsets = contract_format_param_offsets(&format);
        Ok((pool, format, offsets))
    }

    fn expected_guard(operation: u8, word: [u8; 32]) -> [u8; WORD_GUARD_PAYLOAD_LEN] {
        let mut payload = [0u8; WORD_GUARD_PAYLOAD_LEN];
        payload[0] = operation;
        payload[1..].copy_from_slice(&word);
        payload
    }

    fn lombard_fee_approval_format() -> Format {
        serde_json::from_value(serde_json::json!({
            "intent": "Max LBTC fee",
            "fields": [
                {
                    "path": "chainId",
                    "label": "Chain ID",
                    "format": "raw",
                    "visible": "always"
                },
                {
                    "path": "fee",
                    "label": "Base units (hex)",
                    "format": "raw",
                    "visible": "always"
                },
                {
                    "path": "expiry",
                    "label": "Expiry",
                    "format": "date",
                    "visible": "always"
                }
            ]
        }))
        .expect("valid Lombard feeApproval test format")
    }

    fn compile_lombard_fee_approval_test_format(
        ctx: &mut CompileCtx,
        deployment: &InterpolationDeployment<'_>,
        signature: &str,
    ) -> Result<(), String> {
        compile_one_format(
            signature,
            &lombard_fee_approval_format(),
            CTX_EIP712,
            ctx,
            &mut Pool::new(),
            &BTreeMap::new(),
            &mut Vec::new(),
            Some(deployment),
        )
    }

    #[test]
    fn lombard_eip712_word_guard_enrollment_is_exact_and_required() {
        let capabilities = Erc20Capabilities::default();
        let deployment = InterpolationDeployment {
            chain_id: 1,
            contract: LOMBARD_LBTC_MAINNET,
            erc20_capabilities: &capabilities,
        };
        let signature = "feeApproval(uint256 chainId,uint256 fee,uint256 expiry)";
        assert!(eip712_word_guard_required_for(
            Some(&deployment),
            signature,
            LOMBARD_FEE_APPROVAL_TYPE_HASH,
        ));
        let enrollment = eip712_word_guard_enrollment_for(
            LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH,
            Some(&deployment),
            signature,
            LOMBARD_FEE_APPROVAL_TYPE_HASH,
        )
        .expect("exact Lombard descriptor/deployment/type enrollment");
        assert_eq!(enrollment.guards, &LOMBARD_FEE_APPROVAL_GUARDS);
        assert!(eip712_word_guard_enrollment_for(
            [0x55; 32],
            Some(&deployment),
            signature,
            LOMBARD_FEE_APPROVAL_TYPE_HASH,
        )
        .is_none());
    }

    #[test]
    fn lombard_source_boundary_refuses_descriptor_deployment_contract_or_type_drift() {
        let source =
            Path::new("/catalogue").join(LOMBARD_FEE_APPROVAL_SOURCE_SUFFIX);
        assert!(eip712_word_guard_source_required(&source));
        assert!(!eip712_word_guard_source_required(Path::new(
            "/catalogue/registry/lombard/eip712-network-fee-authorization-mainnet-copy.json"
        )));

        let capabilities = Erc20Capabilities::default();
        let exact_deployment = InterpolationDeployment {
            chain_id: 1,
            contract: LOMBARD_LBTC_MAINNET,
            erc20_capabilities: &capabilities,
        };
        let exact_signature = "feeApproval(uint256 chainId,uint256 fee,uint256 expiry)";
        let mut exact_ctx = test_ctx();
        exact_ctx.descriptor_hash = LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH;
        exact_ctx.eip712_word_guard_source_required = true;
        compile_lombard_fee_approval_test_format(
            &mut exact_ctx,
            &exact_deployment,
            exact_signature,
        )
        .expect("exact source identity compiles with its guard");

        let mut drifted_descriptor_ctx = exact_ctx.clone();
        drifted_descriptor_ctx.descriptor_hash[0] ^= 0x80;
        let mut drifted_contract = exact_deployment;
        drifted_contract.contract[0] ^= 0x80;
        let drifted_chain = InterpolationDeployment {
            chain_id: 2,
            ..exact_deployment
        };
        for result in [
            compile_lombard_fee_approval_test_format(
                &mut drifted_descriptor_ctx,
                &exact_deployment,
                exact_signature,
            ),
            compile_lombard_fee_approval_test_format(
                &mut exact_ctx.clone(),
                &drifted_chain,
                exact_signature,
            ),
            compile_lombard_fee_approval_test_format(
                &mut exact_ctx.clone(),
                &drifted_contract,
                exact_signature,
            ),
            compile_lombard_fee_approval_test_format(
                &mut exact_ctx.clone(),
                &exact_deployment,
                "feeApproval(uint256 chainId,uint256 fee,uint64 expiry)",
            ),
        ] {
            let error = result.expect_err("source identity drift must fail closed");
            assert!(
                error.contains("requires an exact descriptor/deployment/type"),
                "unexpected refusal: {error}"
            );
        }
    }

    #[test]
    fn deployment_chain_guard_word_is_derived_from_enrollment_chain() {
        let enrollment = &EIP712_WORD_GUARD_ENROLLMENTS[0];
        validate_eip712_deployment_chain_guard(enrollment.canonical_signature, enrollment)
            .expect("exact chain guard matches deployment");

        const WRONG_CHAIN_GUARDS: [SemanticWordGuard; 1] = [SemanticWordGuard {
            path: "chainId",
            terminal_type: "uint256",
            operation: WORD_GUARD_EQ,
            word: ZERO_WORD,
        }];
        let mut wrong = *enrollment;
        wrong.guards = &WRONG_CHAIN_GUARDS;
        let error = validate_eip712_deployment_chain_guard(wrong.canonical_signature, &wrong)
            .expect_err("copied or stale chain guard word must refuse");
        assert!(
            error.contains("must equal the enrollment chain_id 1"),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn router02_exact_enrollment_emits_only_the_required_sender_and_word_guards() {
        let capabilities = Erc20Capabilities::default();
        let deployment = InterpolationDeployment {
            chain_id: 1,
            contract: ROUTER02_MAINNET,
            erc20_capabilities: &capabilities,
        };

        for exact_input in [true, false] {
            let mut ctx = test_ctx();
            ctx.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
            let (pool, format, offsets) =
                compile_router02_test_format(exact_input, &mut ctx, &deployment)
                    .expect("exact enrollment compiles");
            assert_eq!(offsets.len(), 6, "no synthetic guard-only field");
            assert_eq!(
                &format[..4],
                if exact_input {
                    &[0x04, 0xe4, 0x5a, 0xaf]
                } else {
                    &[0x50, 0x23, 0xb4, 0xdf]
                }
            );

            assert_eq!(
                find_tlv(&pool, offsets[3], PARAM_SENDER_ADDRESS),
                Some(ADDRESS_ONE.as_slice())
            );
            assert_eq!(
                find_tlv(&pool, offsets[3], PARAM_WORD_GUARD),
                Some(expected_guard(WORD_GUARD_NE, ADDRESS_TWO_WORD).as_slice())
            );
            assert_eq!(
                find_tlv(&pool, offsets[4], PARAM_WORD_GUARD),
                Some(expected_guard(WORD_GUARD_EQ, ZERO_WORD).as_slice())
            );
            assert_eq!(
                find_tlv(&pool, offsets[5], PARAM_WORD_GUARD),
                Some(expected_guard(WORD_GUARD_EQ, ZERO_WORD).as_slice())
            );
            assert!(find_tlv(&pool, offsets[1], PARAM_WORD_GUARD).is_none());
            assert!(find_tlv(&pool, offsets[2], PARAM_WORD_GUARD).is_none());
            if exact_input {
                assert_eq!(
                    find_tlv(&pool, offsets[0], PARAM_WORD_GUARD),
                    Some(expected_guard(WORD_GUARD_NE, ZERO_WORD).as_slice())
                );
            } else {
                assert!(find_tlv(&pool, offsets[0], PARAM_WORD_GUARD).is_none());
            }
        }
    }

    #[test]
    fn sender_address_requires_the_complete_exact_enrollment_key() {
        let capabilities = Erc20Capabilities::default();
        let exact = InterpolationDeployment {
            chain_id: 1,
            contract: ROUTER02_MAINNET,
            erc20_capabilities: &capabilities,
        };

        let mut wrong_hash = test_ctx();
        wrong_hash.descriptor_hash = [0x55; 32];
        let error = compile_router02_test_format(true, &mut wrong_hash, &exact)
            .err()
            .expect("descriptor hash mismatch must refuse")
            .to_string();
        assert!(error.contains("without an exact"), "{error}");

        let wrong_chain = InterpolationDeployment {
            chain_id: 10,
            ..exact
        };
        let mut exact_hash = test_ctx();
        exact_hash.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
        let error = compile_router02_test_format(true, &mut exact_hash, &wrong_chain)
            .err()
            .expect("chain mismatch must refuse")
            .to_string();
        assert!(error.contains("without an exact"), "{error}");

        let wrong_contract = InterpolationDeployment {
            contract: [0x44; 20],
            ..exact
        };
        let mut exact_hash = test_ctx();
        exact_hash.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
        let error = compile_router02_test_format(true, &mut exact_hash, &wrong_contract)
            .err()
            .expect("contract mismatch must refuse")
            .to_string();
        assert!(error.contains("without an exact"), "{error}");
    }

    #[test]
    fn packed_v3_path_requires_exact_enrollment_and_reviewed_source_shape() {
        let capabilities = Erc20Capabilities::default();
        let exact = InterpolationDeployment {
            chain_id: 1,
            contract: ROUTER02_MAINNET,
            erc20_capabilities: &capabilities,
        };

        for exact_input in [true, false] {
            let mut ctx = test_ctx();
            ctx.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
            let (pool, format, offsets) =
                compile_router02_packed_test_format(exact_input, &mut ctx, &exact)
                    .expect("exact packed enrollment compiles");
            assert_eq!(offsets.len(), 5);
            assert_eq!(format[4], 5);
            assert_eq!(
                find_tlv(&pool, offsets[3], PARAM_DYNAMIC_KIND),
                Some(&[DYNAMIC_KIND_BYTES][..])
            );

            for (descriptor_hash, deployment) in [
                ([0x55; 32], exact),
                (
                    ROUTER02_DESCRIPTOR_HASH,
                    InterpolationDeployment {
                        chain_id: 10,
                        ..exact
                    },
                ),
                (
                    ROUTER02_DESCRIPTOR_HASH,
                    InterpolationDeployment {
                        contract: [0x44; 20],
                        ..exact
                    },
                ),
            ] {
                let mut ctx = test_ctx();
                ctx.descriptor_hash = descriptor_hash;
                let error = compile_router02_packed_test_format(exact_input, &mut ctx, &deployment)
                    .err()
                    .expect("any enrollment-key mismatch must refuse");
                assert!(
                    error.contains("without an exact")
                        || error.contains("packed V3 path formatter requires"),
                    "{error}"
                );
            }

            let (sig, mut missing_marker) = router02_packed_format(exact_input);
            missing_marker.fields[3].format = Some("raw".to_string());
            let mut ctx = test_ctx();
            ctx.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
            let error = compile_one_format(
                sig,
                &missing_marker,
                CTX_CONTRACT,
                &mut ctx,
                &mut Pool::new(),
                &BTreeMap::new(),
                &mut Vec::new(),
                Some(&exact),
            )
            .expect_err("an enrolled selector without its complete route marker must refuse");
            assert!(
                error.contains("packed V3 path formatter requires"),
                "{error}"
            );

            let (sig, mut wrong_path) = router02_packed_format(exact_input);
            wrong_path.fields[3].path = Some("params.recipient".to_string());
            let mut ctx = test_ctx();
            ctx.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
            let error = compile_one_format(
                sig,
                &wrong_path,
                CTX_CONTRACT,
                &mut ctx,
                &mut Pool::new(),
                &BTreeMap::new(),
                &mut Vec::new(),
                Some(&exact),
            )
            .expect_err("the packed formatter must consume the complete params.path");
            assert!(
                error.contains("full `params.path` field")
                    || error.contains("tuple member `params.path`"),
                "{error}"
            );
        }

        let (sig, unreviewed) = router02_packed_format(true);
        let unrelated_sig = sig.replacen("exactInput", "otherInput", 1);
        let mut ctx = test_ctx();
        ctx.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
        let error = compile_one_format(
            &unrelated_sig,
            &unreviewed,
            CTX_CONTRACT,
            &mut ctx,
            &mut Pool::new(),
            &BTreeMap::new(),
            &mut Vec::new(),
            Some(&exact),
        )
        .expect_err("an unrelated selector must not gain the packed capability");
        assert!(
            error.contains("without an exact")
                || error.contains("packed V3 path formatter requires"),
            "{error}"
        );
    }

    #[test]
    fn exact_enrollment_requires_every_visible_guard_path_once() {
        let capabilities = Erc20Capabilities::default();
        let deployment = InterpolationDeployment {
            chain_id: 1,
            contract: ROUTER02_MAINNET,
            erc20_capabilities: &capabilities,
        };
        let (sig, mut format) = router02_format(true);
        format
            .fields
            .retain(|field| field.path.as_deref() != Some("@.value"));
        let mut pool = Pool::new();
        let mut out = Vec::new();
        let mut exact_hash = test_ctx();
        exact_hash.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
        let error = compile_one_format(
            sig,
            &format,
            CTX_CONTRACT,
            &mut exact_hash,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
            Some(&deployment),
        )
        .expect_err("missing enrolled @.value field must refuse");
        assert!(
            error.contains("`@.value` must be present exactly once"),
            "{error}"
        );

        let (_, mut hidden) = router02_format(true);
        hidden.fields[5].visible = Some("never".to_string());
        let mut pool = Pool::new();
        let mut exact_hash = test_ctx();
        exact_hash.descriptor_hash = ROUTER02_DESCRIPTOR_HASH;
        let error = compile_one_format(
            sig,
            &hidden,
            CTX_CONTRACT,
            &mut exact_hash,
            &mut pool,
            &BTreeMap::new(),
            &mut Vec::new(),
            Some(&deployment),
        )
        .expect_err("hidden enrolled guard field must refuse");
        assert!(
            error.contains("must be always visible") || error.contains("visible:\"never\""),
            "{error}"
        );
    }

    #[test]
    fn sender_address_list_is_canonical_and_bounded() {
        let ctx = test_ctx();
        assert_eq!(
            compile_sender_addresses(
                &serde_json::json!("0x0000000000000000000000000000000000000001"),
                &ctx,
            )
            .unwrap(),
            ADDRESS_ONE
        );
        assert!(compile_sender_addresses(&serde_json::json!([]), &ctx).is_err());
        assert!(compile_sender_addresses(
            &serde_json::json!([
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000001"
            ]),
            &ctx,
        )
        .is_err());
        assert!(compile_sender_addresses(
            &serde_json::json!([
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000003"
            ]),
            &ctx,
        )
        .is_err());
    }

    #[test]
    fn semantic_enrollment_selectors_are_independently_recomputed() {
        assert_eq!(PARAM_SENDER_ADDRESS, 0x49);
        assert_eq!(PARAM_WORD_GUARD, 0x4A);
        assert_eq!(PARAM_EXACT_EMPTY_BYTES, 0x4B);
        assert_eq!(PARAM_EIP712_STRING_PREIMAGE, 0x4C);
        let expected = [
            (
                ROUTER02_MAINNET,
                "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
            ),
            (
                ROUTER02_MAINNET,
                "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
            ),
            (
                ROUTER02_MAINNET,
                "exactInput((bytes,address,uint256,uint256))",
            ),
            (
                ROUTER02_MAINNET,
                "exactOutput((bytes,address,uint256,uint256))",
            ),
            (
                ROUTER02_MAINNET,
                "swapExactTokensForTokens(uint256,uint256,address[],address)",
            ),
            (
                ROUTER02_MAINNET,
                "swapTokensForExactTokens(uint256,uint256,address[],address)",
            ),
            (LIDO_QUEUE_MAINNET, "requestWithdrawals(uint256[],address)"),
            (
                LIDO_QUEUE_MAINNET,
                "requestWithdrawalsWstETH(uint256[],address)",
            ),
        ];
        for (enrollment, (contract, signature)) in
            SEMANTIC_FORMAT_ENROLLMENTS.into_iter().zip(expected)
        {
            let digest = keccak256(enrollment.canonical_signature.as_bytes());
            assert_eq!(enrollment.selector, digest[..4]);
            assert_eq!(enrollment.contract, contract);
            assert_eq!(enrollment.canonical_signature, signature);
            assert_eq!(enrollment.chain_id, 1);
        }
        for deadline_signature in [
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
        ] {
            let digest = keccak256(deadline_signature.as_bytes());
            assert!(
                !SEMANTIC_FORMAT_ENROLLMENTS
                    .iter()
                    .any(|enrollment| enrollment.selector == digest[..4]),
                "five-argument deadline route must not inherit four-argument Router02 authority"
            );
        }

        for enrollment in EXACT_EMPTY_BYTES_ENROLLMENTS {
            let digest = keccak256(enrollment.canonical_signature.as_bytes());
            assert_eq!(enrollment.selector, digest[..4]);
            assert_eq!(enrollment.contract, MORPHO_BLUE);
            assert!(matches!(enrollment.chain_id, 1 | 8_453));
            assert_eq!(enrollment.path, "#.data");
        }
        assert_eq!(
            EXACT_EMPTY_BYTES_ENROLLMENTS
                .iter()
                .map(|entry| (entry.chain_id, entry.selector))
                .collect::<BTreeSet<_>>()
                .len(),
            EXACT_EMPTY_BYTES_ENROLLMENTS.len(),
            "every exact-empty enrollment key must be unique"
        );
    }

    #[test]
    fn exact_empty_bytes_enrollment_requires_the_complete_morpho_key() {
        let capabilities = Erc20Capabilities::default();
        let exact = InterpolationDeployment {
            chain_id: 1,
            contract: MORPHO_BLUE,
            erc20_capabilities: &capabilities,
        };
        let signature =
            "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)";
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4].try_into().unwrap();
        assert!(exact_empty_bytes_enrollment_for(
            MORPHO_BLUE_DESCRIPTOR_HASH,
            Some(&exact),
            signature,
            selector,
        )
        .is_some());
        assert!(
            exact_empty_bytes_enrollment_for([0x55; 32], Some(&exact), signature, selector,)
                .is_none()
        );
        assert!(exact_empty_bytes_enrollment_for(
            MORPHO_BLUE_DESCRIPTOR_HASH,
            Some(&InterpolationDeployment {
                chain_id: 10,
                ..exact
            }),
            signature,
            selector,
        )
        .is_none());
        assert!(exact_empty_bytes_enrollment_for(
            MORPHO_BLUE_DESCRIPTOR_HASH,
            Some(&InterpolationDeployment {
                contract: [0x44; 20],
                ..exact
            }),
            signature,
            selector,
        )
        .is_none());
        assert!(exact_empty_bytes_enrollment_for(
            MORPHO_BLUE_DESCRIPTOR_HASH,
            Some(&exact),
            "other(bytes)",
            selector,
        )
        .is_none());
        let mut wrong_selector = selector;
        wrong_selector[0] ^= 1;
        assert!(exact_empty_bytes_enrollment_for(
            MORPHO_BLUE_DESCRIPTOR_HASH,
            Some(&exact),
            signature,
            wrong_selector,
        )
        .is_none());
    }

    #[test]
    fn production_eip712_string_enrollment_table_is_empty() {
        assert!(
            EIP712_STRING_PREIMAGE_ENROLLMENTS.is_empty(),
            "production string-preimage authority requires a new evidence-backed admission"
        );

        let capabilities = Erc20Capabilities::default();
        let deployment = synthetic_eip712_string_deployment(&capabilities);
        assert!(eip712_string_preimage_enrollment_for(
            SYNTHETIC_EIP712_STRING_DESCRIPTOR_HASH,
            Some(&deployment),
            SYNTHETIC_EIP712_STRING_SIGNATURE,
            keccak256(SYNTHETIC_EIP712_STRING_SIGNATURE.as_bytes()),
        )
        .is_none());
    }

    #[test]
    fn production_catalogue_emits_no_eip712_string_preimage_authority() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let registry_parent = root.join("secure/data/erc7730-registry");
        let registry_root = registry_parent.join("registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let (catalogue, _) = build_db_tolerant(&registry_root, &policy, Some(&registry_parent))
            .expect("build production catalogue");

        for entry in &catalogue.entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("device accepts emitted IR");
            for format in ir.format_iter() {
                let format = format.expect("canonical production format");
                assert_eq!(
                    format.string_preimage_count,
                    0,
                    "stale string-preimage header authority in {}",
                    entry.source.display()
                );
                for field in format.fields() {
                    let field = field.expect("canonical production field");
                    let params = pqsigner_erc7730::render::params::parse(&ir, field.param_off)
                        .expect("canonical production params");
                    assert_eq!(
                        params.eip712_string_preimage_ordinal,
                        None,
                        "stale string-preimage field authority in {}",
                        entry.source.display()
                    );
                }
            }
        }
    }

    #[test]
    fn production_router02_tolerant_compile_emits_all_six_guarded_formats() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root
            .join("secure/data/erc7730-registry/registry/uniswap/calldata-UniswapV3Router02.json");
        let mut drops = Vec::new();
        let entries = compile_descriptor(
            &descriptor,
            &Policy::default(),
            None,
            true,
            &mut drops,
            &Erc20Capabilities::default(),
            None,
        )
        .expect("tolerant Router02 compile");
        assert_eq!(entries.len(), 1, "one exact mainnet deployment leaf");
        let entry = &entries[0];
        assert_eq!(entry.descriptor_hash, ROUTER02_DESCRIPTOR_HASH);
        assert_eq!((entry.chain_id, entry.contract), (1, ROUTER02_MAINNET));

        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("device accepts emitted Router02 IR");
        let formats: Vec<_> = ir
            .format_iter()
            .map(|format| format.expect("canonical format"))
            .collect();
        let selectors: BTreeSet<_> = formats.iter().map(|format| format.selector).collect();
        assert_eq!(
            selectors,
            BTreeSet::from([
                [0x04, 0xe4, 0x5a, 0xaf],
                [0x50, 0x23, 0xb4, 0xdf],
                [0xb8, 0x58, 0x18, 0x3f],
                [0x09, 0xb8, 0x13, 0x46],
                [0x47, 0x2b, 0x43, 0xf3],
                [0x42, 0x71, 0x2a, 0x67],
            ])
        );

        for (selector, exact_input) in [
            ([0xb8, 0x58, 0x18, 0x3f], true),
            ([0x09, 0xb8, 0x13, 0x46], false),
        ] {
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Router02 format table parses")
                .expect("enrolled packed-route selector");
            assert_eq!(format.static_head_words, 1);
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("packed Router02 field parses"))
                .collect();
            assert_eq!(fields.len(), 5);
            assert_eq!(fields[0].label, b"Native value");
            assert_eq!(fields[3].format_op, FMT_UNISWAP_V3_PATH);
            assert_eq!(fields[3].label, b"Route");
            assert_eq!(fields[4].label, b"Beneficiary");
            assert_eq!(
                ir.path_bytes(fields[3].path_off)
                    .expect("packed route path parses"),
                [
                    PATHOP_ROOT_STRUCT,
                    PATHOP_FIELD_IDX,
                    0,
                    0,
                    PATHOP_FOLLOW_OFFSET,
                    PATHOP_FIELD_IDX,
                    0,
                    0,
                    PATHOP_FOLLOW_OFFSET,
                ]
            );

            let params: Vec<_> = fields
                .iter()
                .map(|field| {
                    pqsigner_erc7730::render::params::parse(&ir, field.param_off)
                        .expect("packed Router02 params parse")
                })
                .collect();
            assert_eq!(params[3].dynamic_kind, Some(DYNAMIC_KIND_BYTES));
            assert!(params[3].token_path.is_none());
            assert_eq!(params[4].sender_addresses, Some(ADDRESS_ONE.as_slice()));
            assert_eq!(
                params[0].word_guard.expect("value guard").mode(),
                WORD_GUARD_EQ
            );
            assert_eq!(
                params[0].word_guard.expect("value guard").expected(),
                &ZERO_WORD
            );
            assert_eq!(
                params[4].word_guard.expect("recipient guard").mode(),
                WORD_GUARD_NE
            );
            assert_eq!(
                params[4].word_guard.expect("recipient guard").expected(),
                &ADDRESS_TWO_WORD
            );
            if exact_input {
                assert_eq!(
                    params[1].word_guard.expect("input guard").mode(),
                    WORD_GUARD_NE
                );
                assert_eq!(
                    params[1].word_guard.expect("input guard").expected(),
                    &ZERO_WORD
                );
            } else {
                assert!(params[1].word_guard.is_none());
            }
            assert!(params[2].word_guard.is_none());
            assert!(params[3].word_guard.is_none());
        }

        for (selector, exact_input) in [
            ([0x47, 0x2b, 0x43, 0xf3], true),
            ([0x42, 0x71, 0x2a, 0x67], false),
        ] {
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Router02 format table parses")
                .expect("enrolled full-route selector");
            let fields: Vec<_> = format
                .fields()
                .map(|field| field.expect("Router02 field parses"))
                .collect();
            assert_eq!(fields.len(), 5);
            assert_eq!(fields[0].label, b"Native value");
            assert_eq!(
                fields[1].label,
                if exact_input {
                    b"Swap input".as_slice()
                } else {
                    b"Amount to receive".as_slice()
                }
            );
            assert_eq!(
                fields[2].label,
                if exact_input {
                    b"Minimum receive".as_slice()
                } else {
                    b"Max swap input".as_slice()
                }
            );
            assert_eq!(fields[3].label, b"Route");
            assert_eq!(fields[4].label, b"Beneficiary");
            assert_eq!(
                ir.path_bytes(fields[3].path_off)
                    .expect("full route path parses"),
                [PATHOP_ROOT_STRUCT, PATHOP_FIELD_IDX, 0, 2, PATHOP_ARRAY_ALL,]
            );

            let params: Vec<_> = fields
                .iter()
                .map(|field| {
                    pqsigner_erc7730::render::params::parse(&ir, field.param_off)
                        .expect("Router02 params parse")
                })
                .collect();
            assert_eq!(params[3].addr_types, Some(ADDR_TYPE_TOKEN));
            assert_eq!(params[4].sender_addresses, Some(ADDRESS_ONE.as_slice()));
            assert_eq!(
                params[0].word_guard.expect("value guard").mode(),
                WORD_GUARD_EQ
            );
            assert_eq!(
                params[0].word_guard.expect("value guard").expected(),
                &ZERO_WORD
            );
            assert_eq!(
                params[4].word_guard.expect("recipient guard").mode(),
                WORD_GUARD_NE
            );
            assert_eq!(
                params[4].word_guard.expect("recipient guard").expected(),
                &ADDRESS_TWO_WORD
            );
            if exact_input {
                assert_eq!(
                    params[1].word_guard.expect("input guard").expected(),
                    &ZERO_WORD
                );
            } else {
                assert!(params[1].word_guard.is_none());
            }
            assert!(params[2].word_guard.is_none());
            assert!(params[3].word_guard.is_none());
        }
        assert!(
            drops.is_empty(),
            "all six Router02 formats are complete and enrolled: {drops:#?}"
        );
    }

    #[test]
    fn production_lido_queue_tolerant_compile_emits_both_sender_bound_request_routes() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root
            .join("secure/data/erc7730-registry/registry/lido/calldata-WithdrawalQueueERC721.json");
        let erc20 = crate::erc20::build_db(&root.join("secure/data/erc20.json"))
            .expect("build production ERC20 capabilities");
        let mut drops = Vec::new();
        let entries = compile_descriptor(
            &descriptor,
            &Policy::default(),
            None,
            true,
            &mut drops,
            &erc20.capabilities,
            None,
        )
        .expect("tolerant Lido queue compile");
        assert_eq!(entries.len(), 1, "one exact mainnet deployment leaf");
        let entry = &entries[0];
        assert_eq!(entry.descriptor_hash, LIDO_QUEUE_DESCRIPTOR_HASH);
        assert_eq!((entry.chain_id, entry.contract), (1, LIDO_QUEUE_MAINNET));

        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("device accepts emitted Lido IR");
        let selectors: BTreeSet<_> = ir
            .format_iter()
            .map(|format| format.expect("canonical format").selector)
            .collect();
        for selector in [[0xd6, 0x68, 0x10, 0x42], [0x19, 0xaa, 0x62, 0x57]] {
            assert!(
                selectors.contains(&selector),
                "missing selector 0x{}; present={:?}; drops={drops:#?}",
                hex::encode(selector),
                selectors
            );
        }
        assert_eq!(selectors.len(), 7, "five legacy plus two request routes");
        assert_eq!(drops.len(), 4, "permit and batch-claim routes stay refused");
    }

    /// Owner utility for replacing
    /// `ROUTER02_DESCRIPTOR_HASH`. This is intentionally
    /// ignored during ordinary tests because it reads the checked-in corpus.
    #[test]
    #[ignore = "owner utility: prints SHA-256(JCS(resolved Router02 descriptor))"]
    fn print_router02_descriptor_hash_after_curation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root.join(
            "secure/data/erc7730/curations/files/registry/uniswap/calldata-UniswapV3Router02.json",
        );
        let json = load_resolved_descriptor_json(&descriptor, None).expect("load descriptor");
        let hash = sha256_of(&jcs_canonicalize(&json).expect("JCS descriptor"));
        eprintln!(
            "Router02 semantic enrollment descriptor hash: 0x{}",
            hex::encode(hash)
        );
        assert_eq!(
            hash, ROUTER02_DESCRIPTOR_HASH,
            "semantic enrollment must remain bound to exact final curation"
        );
    }

    /// Owner utility for replacing `LIDO_QUEUE_DESCRIPTOR_HASH` after an
    /// intentional curation update.
    #[test]
    #[ignore = "owner utility: prints SHA-256(JCS(resolved Lido queue descriptor))"]
    fn print_lido_queue_descriptor_hash_after_curation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root.join(
            "secure/data/erc7730/curations/files/registry/lido/calldata-WithdrawalQueueERC721.json",
        );
        let json = load_resolved_descriptor_json(&descriptor, None).expect("load descriptor");
        let hash = sha256_of(&jcs_canonicalize(&json).expect("JCS descriptor"));
        eprintln!(
            "Lido queue semantic enrollment descriptor hash: 0x{}",
            hex::encode(hash)
        );
        assert_eq!(
            hash, LIDO_QUEUE_DESCRIPTOR_HASH,
            "semantic enrollment must remain bound to exact final curation"
        );
    }

    /// Owner utility for replacing `MORPHO_BLUE_DESCRIPTOR_HASH` after an
    /// intentional curation update.
    #[test]
    #[ignore = "owner utility: prints SHA-256(JCS(resolved Morpho Blue descriptor))"]
    fn print_morpho_blue_descriptor_hash_after_curation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root
            .join("secure/data/erc7730/curations/files/registry/morpho/calldata-MorphoBlue.json");
        let json = load_resolved_descriptor_json(&descriptor, None).expect("load descriptor");
        let hash = sha256_of(&jcs_canonicalize(&json).expect("JCS descriptor"));
        eprintln!(
            "Morpho Blue exact-empty enrollment descriptor hash: 0x{}",
            hex::encode(hash)
        );
        assert_eq!(
            hash, MORPHO_BLUE_DESCRIPTOR_HASH,
            "exact-empty enrollment must remain bound to exact final curation"
        );
    }

    /// Owner utility for replacing `LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH`
    /// after an intentional display or semantic curation update.
    #[test]
    #[ignore = "owner utility: prints SHA-256(JCS(resolved Lombard feeApproval descriptor))"]
    fn print_lombard_fee_approval_descriptor_hash_after_curation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let descriptor = root.join(
            "secure/data/erc7730/curations/files/registry/lombard/eip712-network-fee-authorization-mainnet.json",
        );
        let json = load_resolved_descriptor_json(&descriptor, None).expect("load descriptor");
        let hash = sha256_of(&jcs_canonicalize(&json).expect("JCS descriptor"));
        eprintln!(
            "Lombard feeApproval semantic enrollment descriptor hash: 0x{}",
            hex::encode(hash)
        );
        assert_eq!(
            hash, LOMBARD_FEE_APPROVAL_DESCRIPTOR_HASH,
            "semantic enrollment must remain bound to exact final curation"
        );
    }

    #[test]
    fn native_currency_scalar_and_singleton_list_keep_legacy_bytes() {
        const ETH: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let ctx = test_ctx();
        let expected = [0xEEu8; 20];
        let scalar = compile_native_currency_addresses(&serde_json::json!(ETH), &ctx).unwrap();
        let singleton = compile_native_currency_addresses(&serde_json::json!([ETH]), &ctx).unwrap();
        assert_eq!(scalar, expected);
        assert_eq!(singleton, expected);
    }

    #[test]
    fn native_currency_list_resolves_constants_in_descriptor_order() {
        const ETH: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        const ZERO: &str = "0x0000000000000000000000000000000000000000";
        let mut ctx = test_ctx();
        ctx.constants.insert(
            "addressAsEth".to_string(),
            serde_json::Value::String(ETH.to_string()),
        );
        ctx.constants.insert(
            "addressAsNull".to_string(),
            serde_json::Value::String(ZERO.to_string()),
        );
        let value = serde_json::json!([
            "$.metadata.constants.addressAsEth",
            "$.metadata.constants.addressAsNull"
        ]);
        let compiled = compile_native_currency_addresses(&value, &ctx).unwrap();
        assert_eq!(compiled.len(), 40);
        assert_eq!(&compiled[..20], &[0xEE; 20]);
        assert_eq!(&compiled[20..], &[0x00; 20]);
    }

    #[test]
    fn native_currency_list_rejects_invalid_shapes_and_members() {
        const ETH: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        const ZERO: &str = "0x0000000000000000000000000000000000000000";
        let ctx = test_ctx();
        for (value, expected) in [
            (serde_json::json!([]), "must not be empty"),
            (
                serde_json::json!([ETH, ZERO, "0x1111111111111111111111111111111111111111"]),
                "max 2",
            ),
            (serde_json::json!([ETH, 1]), "must be a string"),
            (serde_json::json!([ETH, ETH]), "duplicates"),
            (serde_json::json!(["0xeee"]), "40 hex chars"),
            (serde_json::json!(7), "string or string array"),
        ] {
            let err = compile_native_currency_addresses(&value, &ctx).unwrap_err();
            assert!(err.contains(expected), "expected {expected:?}, got {err:?}");
        }
    }

    fn compile_nft_field(sig: &str, params: serde_json::Value) -> Result<(Pool, u16), String> {
        let parsed = parse_format_key(sig)?;
        let field: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "tokenId",
            "label": "NFT",
            "format": "nftName",
            "params": params
        }))
        .map_err(|e| e.to_string())?;
        let mut pool = Pool::new();
        let compiled = compile_one_field(
            sig,
            0,
            &field,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut pool,
            &BTreeMap::new(),
            false,
        )?;
        Ok((pool, compiled.param_off))
    }

    #[test]
    fn nft_collection_literal_and_to_path_emit_dedicated_tlvs() {
        const COLLECTION: &str = "0xa4215Daaf3745E14E96E169E0E7706c479Ce04F2";
        let (literal_pool, literal_off) = compile_nft_field(
            "approve(address to,uint256 tokenId)",
            serde_json::json!({ "collection": COLLECTION }),
        )
        .unwrap();
        assert_eq!(
            find_tlv(&literal_pool, literal_off, PARAM_NFT_COLLECTION),
            Some(&hex::decode(&COLLECTION[2..]).unwrap()[..])
        );
        assert!(find_tlv(&literal_pool, literal_off, PARAM_NFT_COLLECTION_PATH).is_none());

        let (path_pool, path_off) = compile_nft_field(
            "approve(address to,uint256 tokenId)",
            serde_json::json!({ "collectionPath": "@.to" }),
        )
        .unwrap();
        assert_eq!(
            find_tlv(&path_pool, path_off, PARAM_NFT_COLLECTION_PATH),
            Some(NFT_COLLECTION_TO_PATH.as_slice()),
            "compiler output must be byte-identical to the device allowlist"
        );
        let parsed = parse_format_key("approve(address to,uint256 tokenId)").unwrap();
        assert_eq!(
            compile_path("@.to", CTX_CONTRACT, &parsed).unwrap(),
            NFT_COLLECTION_TO_PATH,
            "shared compiler/device path parity drift"
        );
    }

    #[test]
    fn nft_collection_path_rejects_every_non_to_program_and_requires_one_source() {
        let sig = "f(uint256 tokenId,address collection)";

        for (params, expected) in [
            (serde_json::json!({}), "exactly one"),
            (
                serde_json::json!({
                    "collection": "0x1111111111111111111111111111111111111111",
                    "collectionPath": "@.to"
                }),
                "exactly one",
            ),
            (
                serde_json::json!({ "collectionPath": "collection" }),
                "exact device-supported `@.to`",
            ),
            (
                serde_json::json!({ "collectionPath": "tokenId" }),
                "exact device-supported `@.to`",
            ),
            (
                serde_json::json!({ "collectionPath": "@.from" }),
                "exact device-supported `@.to`",
            ),
        ] {
            let error = match compile_nft_field(sig, params) {
                Ok(_) => panic!("malformed nftName parameters unexpectedly compiled"),
                Err(error) => error,
            };
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?}"
            );
        }
    }

    fn synthetic_eip712_entry(
        source: &str,
        chain_id: u64,
        contract_byte: u8,
        domain_separator: [u8; 32],
        display: Display,
    ) -> Emitted {
        let mut ctx = test_ctx();
        ctx.descriptor_hash = [contract_byte; 32];
        let primary_type_hash = display
            .formats
            .keys()
            .next()
            .map(|sig| keccak256(sig.as_bytes()))
            .unwrap();
        let (formats, pool) = compile_formats(&display, CTX_EIP712, &mut ctx, false).unwrap();
        let contract = [contract_byte; 20];
        let ir_bytes = build_ir(
            CTX_EIP712,
            chain_id,
            contract,
            &domain_separator,
            &ctx,
            &pool,
            &formats,
        )
        .unwrap();
        Emitted {
            source: PathBuf::from(source),
            descriptor_id: source.to_string(),
            descriptor_hash: ctx.descriptor_hash,
            erc8176_hash: [0; 32],
            chain_id,
            contract,
            context_kind: CTX_EIP712,
            primary_type_hash,
            ir_bytes,
            leaf_index: 0,
        }
    }

    #[test]
    fn erc8176_threshold_filters_all_deployments_once_per_resolved_source() {
        let make_entry = |source: &str, hash_byte: u8, contract_byte: u8| Emitted {
            source: PathBuf::from(source),
            descriptor_id: source.to_string(),
            descriptor_hash: [hash_byte; 32],
            erc8176_hash: [hash_byte; 32],
            chain_id: 1,
            contract: [contract_byte; 20],
            context_kind: CTX_CONTRACT,
            primary_type_hash: [0; 32],
            ir_bytes: vec![contract_byte],
            leaf_index: 0,
        };
        let mut entries = vec![
            make_entry("accepted.json", 0x11, 1),
            make_entry("excluded.json", 0x22, 2),
            make_entry("excluded.json", 0x22, 3),
        ];
        let mut skips = Vec::new();

        retain_erc8176_threshold_entries_with(
            &mut entries,
            2,
            |hash| usize::from(hash == [0x11; 32]) * 2 + usize::from(hash == [0x22; 32]),
            &mut skips,
        );

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, Path::new("accepted.json"));
        assert_eq!(
            skips.len(),
            1,
            "two deployments share one exclusion receipt"
        );
        assert_eq!(skips[0].source, Path::new("excluded.json"));
        assert!(skips[0].reason.contains("attestation threshold"));
        assert!(skips[0].reason.contains("has 1 distinct"));
        assert!(skips[0].reason.contains("requires 2"));
    }

    #[test]
    fn authenticated_snapshot_filters_catalogue_but_preserves_known_call_refusal() {
        let temp = tempfile::tempdir().expect("temporary catalogue");
        let dir = temp.path();
        let accepted_path = dir.join("calldata-accepted.json");
        let excluded_path = dir.join("calldata-excluded.json");
        let snapshot_path = dir.join("erc8176.snapshot");
        let policy_path = dir.join("policy.toml");
        let accepted_descriptor = r#"{
  "context":{"contract":{"deployments":[
    {"chainId":1,"address":"0x0000000000000000000000000000000000000001"},
    {"chainId":10,"address":"0x0000000000000000000000000000000000000002"}
  ]}},
  "metadata":{"owner":"Threshold","contractName":"Accepted"},
  "display":{"formats":{"transfer(address to,uint256 amount)":{"intent":"Send","fields":[
    {"path":"to","format":"addressName","label":"To","visible":"always"},
    {"path":"amount","format":"raw","label":"Amount","visible":"always"}
  ]}}}
}"#;
        let excluded_descriptor = r#"{
  "context":{"contract":{"deployments":[
    {"chainId":1,"address":"0x0000000000000000000000000000000000000003"}
  ]}},
  "metadata":{"owner":"Threshold","contractName":"Excluded"},
  "display":{"formats":{"transfer(address to,uint256 amount)":{"intent":"Send","fields":[
    {"path":"to","format":"addressName","label":"To","visible":"always"},
    {"path":"amount","format":"raw","label":"Amount","visible":"always"}
  ]}}}
}"#;
        fs::write(&accepted_path, accepted_descriptor).unwrap();
        fs::write(&excluded_path, excluded_descriptor).unwrap();

        let accepted_json = load_resolved_descriptor_json(&accepted_path, None).unwrap();
        let accepted_hash = keccak256(&jcs_canonicalize(&accepted_json).unwrap());
        let fixture = crate::erc8176::synthetic_snapshot_fixture(accepted_hash);
        let attesters: Vec<[u8; 20]> = fixture.trusted_attesters.iter().copied().collect();
        assert_eq!(attesters.len(), 2);

        let write_policy = |snapshot_bytes: &[u8]| {
            fs::write(&snapshot_path, snapshot_bytes).unwrap();
            fs::write(
                &policy_path,
                format!(
                    concat!(
                        "min_attesters = 2\n",
                        "trusted_attesters = [\n",
                        "  \"eip155:1:0x{}\",\n",
                        "  \"eip155:1:0x{}\",\n",
                        "]\n",
                        "allow_unattested_dev_descriptors = false\n\n",
                        "[erc8176_snapshot]\n",
                        "path = \"erc8176.snapshot\"\n",
                        "sha256 = \"0x{}\"\n",
                        "block_hash = \"0x{}\"\n",
                        "block_number = {}\n",
                        "block_timestamp = {}\n",
                        "evaluation_time = {}\n",
                        "max_checkpoint_age_secs = {}\n",
                        "min_remaining_validity_secs = {}\n"
                    ),
                    hex::encode(attesters[0]),
                    hex::encode(attesters[1]),
                    hex::encode(sha256_of(snapshot_bytes)),
                    hex::encode(fixture.anchor.checkpoint_block_hash),
                    fixture.anchor.checkpoint_block_number,
                    fixture.checkpoint_timestamp,
                    fixture.anchor.evaluation_timestamp,
                    fixture.anchor.max_checkpoint_age_seconds,
                    fixture.anchor.min_remaining_validity_seconds,
                ),
            )
            .unwrap();
        };

        write_policy(&fixture.raw);
        let (result, skips) = build_db_tolerant(dir, &policy_path, None)
            .expect("two-attester snapshot must authorize exact descriptor");
        assert_eq!(result.provenance, CatalogueProvenance::Erc8176Verified);
        assert_eq!(result.leaf_count, 2, "both attested deployments survive");
        assert!(result
            .entries
            .iter()
            .all(|entry| entry.erc8176_hash == accepted_hash));
        let selector = {
            let hash = keccak256(b"transfer(address,uint256)");
            [hash[0], hash[1], hash[2], hash[3]]
        };
        let mut excluded_contract = [0u8; 20];
        excluded_contract[19] = 3;
        assert!(result
            .known_calls
            .contains(&(1, excluded_contract, selector)));
        assert!(known_call_may_contain(
            &result.known_calls_bloom,
            1,
            &excluded_contract,
            &selector
        ));
        let threshold_skips: Vec<&SkipReport> = skips
            .iter()
            .filter(|skip| skip.reason.contains("ERC-8176 attestation threshold"))
            .collect();
        assert_eq!(threshold_skips.len(), 1);
        assert_eq!(threshold_skips[0].source, excluded_path);
        assert!(result
            .review_text
            .contains("# Provenance: erc8176-verified\n"));
        assert!(result.review_text.contains(ERC8176_DRAFT_COMMIT));
        assert!(result
            .review_text
            .contains("accepted catalogue: 1 hash(es), 2 leaf/leaves"));
        round_trip_check(&result).unwrap();

        let mut one_attester: serde_json::Value =
            serde_json::from_slice(&fixture.raw).expect("fixture JSON");
        one_attester["attestations"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        one_attester["signer_accounts"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        let one_attester_raw = serde_json::to_vec(&one_attester).unwrap();
        write_policy(&one_attester_raw);
        let error = match build_db_tolerant(dir, &policy_path, None) {
            Ok(_) => panic!("one signer must not satisfy a threshold of two"),
            Err(error) => error,
        };
        assert!(error.contains("no IR entries emitted"), "{error}");

        write_policy(&fixture.raw);
        let mutated = accepted_descriptor.replace(
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000004",
        );
        fs::write(&accepted_path, mutated).unwrap();
        let error = match build_db_tolerant(dir, &policy_path, None) {
            Ok(_) => panic!("deployment mutation changes the attested JCS hash"),
            Err(error) => error,
        };
        assert!(error.contains("no IR entries emitted"), "{error}");
    }

    #[test]
    fn duplicate_eip712_binding_checks_every_full_format_type_hash() {
        let first_display: Display = serde_json::from_value(serde_json::json!({
            "formats": {
                "Alpha(uint256 value)": {
                    "intent": "Alpha display",
                    "fields": [{"path":"value","label":"Alpha","format":"raw"}]
                },
                "Shared(uint256 value)": {
                    "intent": "First shared display",
                    "fields": [{"path":"value","label":"First","format":"raw"}]
                }
            }
        }))
        .unwrap();
        let second_display: Display = serde_json::from_value(serde_json::json!({
            "formats": {
                "Shared(uint256 value)": {
                    "intent": "Competing display",
                    "fields": [{"path":"value","label":"Second","format":"raw"}]
                }
            }
        }))
        .unwrap();
        let domain = [0x44; 32];
        let first = synthetic_eip712_entry("first.json", 1, 0x11, domain, first_display);
        let second = synthetic_eip712_entry("second.json", 1, 0x22, domain, second_display);
        assert_ne!(
            first.primary_type_hash, second.primary_type_hash,
            "the collision must live on a non-primary format of the first leaf"
        );
        let err = reject_duplicate_eip712_format_bindings(&[first.clone(), second.clone()])
            .expect_err("same chain/domain/full type hash must have one trusted display");
        assert!(
            err.contains("duplicate EIP-712 binding")
                && err.contains("first.json")
                && err.contains("second.json")
                && err.contains(&hex::encode(keccak256(b"Shared(uint256 value)"))),
            "unexpected duplicate error: {err}"
        );

        let mut other_domain = second.clone();
        other_domain.ir_bytes[62..94].fill(0x55);
        assert!(
            reject_duplicate_eip712_format_bindings(&[first.clone(), other_domain]).is_ok(),
            "a different canonical domain separator is a different signed domain"
        );

        let mut other_chain = second;
        other_chain.chain_id = 2;
        other_chain.ir_bytes[2..10].copy_from_slice(&2u64.to_be_bytes());
        assert!(
            reject_duplicate_eip712_format_bindings(&[first, other_chain]).is_ok(),
            "the binding key is chain-scoped"
        );
    }

    fn find_tlv<'a>(pool: &'a Pool, off: u16, wanted: u8) -> Option<&'a [u8]> {
        let off = off as usize;
        let len = *pool.buf.get(off)? as usize;
        let body = pool.buf.get(off + 1..off + 1 + len)?;
        let mut p = 0usize;
        while p < body.len() {
            let tag = *body.get(p)?;
            let n = *body.get(p + 1)? as usize;
            let value = body.get(p + 2..p + 2 + n)?;
            if tag == wanted {
                return Some(value);
            }
            p += 2 + n;
        }
        None
    }

    #[test]
    fn interpolated_intent_omits_runtime_token_path_without_deployment_capability() {
        let sig = "deposit(address asset,uint256 amt)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt: Format = serde_json::from_value(serde_json::json!({
            "intent": "Deposit collateral",
            "interpolatedIntent": "Deposit {amt}",
            "fields": [{
                "path": "amt",
                "label": "Amount",
                "format": "tokenAmount",
                "params": { "tokenPath": "asset" },
                "visible": "always"
            }]
        }))
        .unwrap();
        assert_eq!(
            compile_interpolated_intent(sig, &fmt, CTX_CONTRACT, &parsed, &test_ctx(), None,)
                .unwrap(),
            None,
            "a calldata-derived token identity must retain only the static intent"
        );
    }

    #[test]
    fn interpolated_intent_blocks_computed_approve_selector_text_collision() {
        let sig = "watch_tg_invmru_2f69f1b(address first,address second)";
        let parsed = parse_format_key(sig).unwrap();
        assert_ne!(parsed.types_signature, "approve(address,uint256)");
        let hash = keccak256(parsed.types_signature.as_bytes());
        assert_eq!(&hash[..4], ERC20_APPROVE_SELECTOR.as_slice());

        // The malformed template would error if source parsing continued.
        // Selector policy must short-circuit it to static intent based on the
        // computed selector, not on the non-approve source spelling.
        let fmt: Format = serde_json::from_value(serde_json::json!({
            "intent": "Static collision",
            "interpolatedIntent": "Broken {",
            "fields": [
                { "path": "first", "format": "addressName" },
                { "path": "second", "format": "addressName" }
            ]
        }))
        .unwrap();
        assert_eq!(
            compile_interpolated_intent(sig, &fmt, CTX_CONTRACT, &parsed, &test_ctx(), None,)
                .unwrap(),
            None,
            "computed 0x095ea7b3 must never enroll interpolation"
        );
    }

    #[test]
    fn token_amount_interpolation_requires_static_authenticated_deployment_identity() {
        const TOKEN: [u8; 20] = [0x11; 20];
        const NATIVE: [u8; 20] = [0xEE; 20];
        let capabilities = crate::erc20::Erc20Capabilities::from_keys(vec![(1, TOKEN)]);
        let empty = crate::erc20::Erc20Capabilities::default();
        let ctx = test_ctx();

        let literal_sig = "deposit(uint256 amount)";
        let literal_parsed = parse_format_key(literal_sig).unwrap();
        let literal: Format = serde_json::from_value(serde_json::json!({
            "intent": "Deposit",
            "interpolatedIntent": "Deposit {amount}",
            "fields": [{
                "path": "amount",
                "format": "tokenAmount",
                "params": { "token": "0x1111111111111111111111111111111111111111" }
            }]
        }))
        .unwrap();
        let covered = InterpolationDeployment {
            chain_id: 1,
            contract: [0x22; 20],
            erc20_capabilities: &capabilities,
        };
        assert!(compile_interpolated_intent(
            literal_sig,
            &literal,
            CTX_CONTRACT,
            &literal_parsed,
            &ctx,
            Some(&covered),
        )
        .unwrap()
        .is_some());

        let uncovered = InterpolationDeployment {
            chain_id: 146,
            contract: [0x22; 20],
            erc20_capabilities: &capabilities,
        };
        assert_eq!(
            compile_interpolated_intent(
                literal_sig,
                &literal,
                CTX_CONTRACT,
                &literal_parsed,
                &ctx,
                Some(&uncovered),
            )
            .unwrap(),
            None,
            "the same static token must lose interpolation on an uncovered deployment"
        );

        let to_sig = "deposit(address asset,uint256 amount)";
        let to_parsed = parse_format_key(to_sig).unwrap();
        let to_path: Format = serde_json::from_value(serde_json::json!({
            "intent": "Deposit",
            "interpolatedIntent": "Deposit {amount}",
            "fields": [{
                "path": "amount",
                "format": "tokenAmount",
                "params": { "tokenPath": "@.to" }
            }]
        }))
        .unwrap();
        let to_deployment = InterpolationDeployment {
            chain_id: 1,
            contract: TOKEN,
            erc20_capabilities: &capabilities,
        };
        assert!(compile_interpolated_intent(
            to_sig,
            &to_path,
            CTX_CONTRACT,
            &to_parsed,
            &ctx,
            Some(&to_deployment),
        )
        .unwrap()
        .is_some());

        let dynamic: Format = serde_json::from_value(serde_json::json!({
            "intent": "Deposit",
            "interpolatedIntent": "Deposit {amount}",
            "fields": [{
                "path": "amount",
                "format": "tokenAmount",
                "params": {
                    "tokenPath": "asset",
                    "token": "0x1111111111111111111111111111111111111111"
                }
            }]
        }))
        .unwrap();
        assert_eq!(
            compile_interpolated_intent(
                to_sig,
                &dynamic,
                CTX_CONTRACT,
                &to_parsed,
                &ctx,
                Some(&covered),
            )
            .unwrap(),
            None,
            "runtime tokenPath precedence must not borrow a static literal's capability"
        );

        let native: Format = serde_json::from_value(serde_json::json!({
            "intent": "Deposit",
            "interpolatedIntent": "Deposit {amount}",
            "fields": [{
                "path": "amount",
                "format": "tokenAmount",
                "params": {
                    "token": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "nativeCurrencyAddress": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                }
            }]
        }))
        .unwrap();
        let native_deployment = InterpolationDeployment {
            chain_id: 146,
            contract: NATIVE,
            erc20_capabilities: &empty,
        };
        assert!(compile_interpolated_intent(
            literal_sig,
            &native,
            CTX_CONTRACT,
            &literal_parsed,
            &ctx,
            Some(&native_deployment),
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn interpolated_intent_rejects_ambiguous_or_nonvisible_amount_refs() {
        let sig = "f(uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        for format in [
            serde_json::json!({
                "interpolatedIntent": "Send {amount}",
                "fields": [{"path":"amount","format":"amount","visible":"optional"}]
            }),
            serde_json::json!({
                "interpolatedIntent": "Send {amount} then {amount}",
                "fields": [{"path":"amount","format":"amount"}]
            }),
            serde_json::json!({
                "interpolatedIntent": "Send {{amount}",
                "fields": [{"path":"amount","format":"amount"}]
            }),
        ] {
            let fmt: Format = serde_json::from_value(format).unwrap();
            assert!(
                compile_interpolated_intent(sig, &fmt, CTX_CONTRACT, &parsed, &test_ctx(), None,)
                    .is_err(),
                "unsafe interpolation unexpectedly compiled"
            );
        }

        let unresolved: Format = serde_json::from_value(serde_json::json!({
            "intent": "Send",
            "interpolatedIntent": "Send {missing}",
            "fields": [{"path":"amount","format":"amount"}]
        }))
        .unwrap();
        assert_eq!(
            compile_interpolated_intent(
                sig,
                &unresolved,
                CTX_CONTRACT,
                &parsed,
                &test_ctx(),
                None,
            )
            .unwrap(),
            None,
            "an unresolvable valid template must retain its static intent"
        );
    }

    #[test]
    fn interpolated_intent_accepts_only_the_optional_structured_root_alias() {
        let sig = "f(uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let rooted: Format = serde_json::from_value(serde_json::json!({
            "interpolatedIntent": "Send {amount}",
            "fields": [{"path":"#.amount","format":"amount"}]
        }))
        .unwrap();
        assert!(compile_interpolated_intent(
            sig,
            &rooted,
            CTX_CONTRACT,
            &parsed,
            &test_ctx(),
            None,
        )
        .unwrap()
        .is_some());

        let ambiguous: Format = serde_json::from_value(serde_json::json!({
            "interpolatedIntent": "Send {amount}",
            "fields": [
                {"path":"amount","format":"amount"},
                {"path":"#.amount","format":"amount"}
            ]
        }))
        .unwrap();
        assert!(
            compile_interpolated_intent(sig, &ambiguous, CTX_CONTRACT, &parsed, &test_ctx(), None,)
                .is_err(),
            "two emitted spellings of one normalized path must be ambiguous"
        );
    }

    #[test]
    fn unsupported_interpolation_shapes_keep_static_intent_without_a_program() {
        let cases = [
            (
                "send(address recipient,uint256 amount)",
                serde_json::json!({
                    "intent":"Send",
                    "interpolatedIntent":"Send to {recipient}",
                    "fields":[
                        {"path":"recipient","format":"addressName"},
                        {"path":"amount","format":"amount"}
                    ]
                }),
                CTX_CONTRACT,
            ),
            (
                "f(uint256[] amounts)",
                serde_json::json!({
                    "intent":"Send",
                    "interpolatedIntent":"Send {amounts.[]}",
                    "fields":[{"path":"amounts.[]","format":"tokenAmount"}]
                }),
                CTX_CONTRACT,
            ),
            (
                "Order(uint256 amount)",
                serde_json::json!({
                    "intent":"Order",
                    "interpolatedIntent":"Order {amount}",
                    "fields":[{"path":"amount","format":"amount"}]
                }),
                CTX_EIP712,
            ),
            (
                "approve(address spender,uint256 amount)",
                serde_json::json!({
                    "intent":"Approve",
                    "interpolatedIntent":"Approve {amount}",
                    "fields":[
                        {"path":"spender","format":"addressName"},
                        {"path":"amount","format":"tokenAmount","params":{"tokenPath":"@.to"}}
                    ]
                }),
                CTX_CONTRACT,
            ),
            (
                "f(uint256 amount)",
                serde_json::json!({
                    "intent":"Send",
                    "interpolatedIntent":"Send {amount} TOKEN",
                    "fields":[{"path":"amount","format":"tokenAmount","params":{"token":"0x1111111111111111111111111111111111111111"}}]
                }),
                CTX_CONTRACT,
            ),
        ];
        for (sig, value, context) in cases {
            let parsed = parse_format_key(sig).unwrap();
            let fmt: Format = serde_json::from_value(value).unwrap();
            assert_eq!(
                compile_interpolated_intent(sig, &fmt, context, &parsed, &test_ctx(), None,)
                    .unwrap(),
                None,
                "unsupported shape must retain static intent: {sig}"
            );
        }
    }

    #[test]
    fn format_level_interpolation_tlv_clones_interned_params_before_append() {
        let mut pool = Pool::new();
        let original_body = [PARAM_DECIMALS, 1, 6];
        let original = intern_param_blob(&mut pool, &original_body).unwrap();
        let program = [INTERPOLATED_INTENT_VERSION, 1, 0, 0, 0];
        let extended = pool
            .append_param_tlv(original, PARAM_INTERPOLATED_INTENT, &program)
            .unwrap();
        assert_ne!(original, extended);
        assert!(find_tlv(&pool, original, PARAM_INTERPOLATED_INTENT).is_none());
        assert_eq!(
            find_tlv(&pool, extended, PARAM_INTERPOLATED_INTENT),
            Some(&program[..])
        );
        assert_eq!(find_tlv(&pool, extended, PARAM_DECIMALS), Some(&[6][..]));
    }

    #[test]
    fn review_param_semantics_decodes_new_security_tlvs_canonically() {
        use pqsigner_erc7730::ir::Visibility;
        use pqsigner_erc7730::render::params::{
            InterpolatedIntentProgram, ParamSet, INTERPOLATED_INTENT_VERSION,
        };

        let native = [0xEEu8; 40];
        let collection = [0xA4u8; 20];
        let collection_path = [
            PATHOP_ROOT_CONTAINER,
            PATHOP_FIELD_IDX,
            (pqsigner_erc7730::abi::container_field::TO >> 8) as u8,
            pqsigner_erc7730::abi::container_field::TO as u8,
        ];
        let interpolation = [
            INTERPOLATED_INTENT_VERSION,
            1,
            8,
            b'D',
            b'e',
            b'p',
            b'o',
            b's',
            b'i',
            b't',
            b' ',
            0,
            0,
        ];
        let mut params = ParamSet::default();
        params.visibility = Visibility::Optional;
        params.native_currency_addresses = Some(&native);
        params.terminal_kind = Some(TerminalKind::Unsigned);
        params.integer_width_bytes = Some(20);
        params.interpolated_intent = Some(
            InterpolatedIntentProgram::parse(&interpolation).expect("canonical interpolation"),
        );

        let decoded = review_param_semantics(&params).expect("review semantics");
        assert!(decoded.contains(&format!(
            "nativeCurrency=[0x{},0x{}]",
            hex::encode(&native[..20]),
            hex::encode(&native[20..]),
        )));
        assert!(decoded.contains("visibility=optional"));
        assert!(decoded.contains("terminalKind=unsigned(0x01)"));
        assert!(decoded.contains("integerWidthBytes=20"));
        assert!(decoded.contains(
            "interpolatedIntent={version=1,count=1,literals=[\"Deposit \",\"\"],ordinals=[0]}"
        ));

        let mut literal_nft = ParamSet::default();
        literal_nft.nft_collection = Some(&collection);
        assert!(review_param_semantics(&literal_nft)
            .unwrap()
            .contains(&format!("nftCollection=0x{}", hex::encode(collection))));
        let mut path_nft = ParamSet::default();
        path_nft.nft_collection_path = Some(&collection_path);
        assert!(review_param_semantics(&path_nft)
            .unwrap()
            .contains(&format!(
                "nftCollectionPath=0x{}",
                hex::encode(collection_path)
            )));

        let mut exact_empty = ParamSet::default();
        exact_empty.dynamic_kind = Some(pqsigner_erc7730::render::params::DYNAMIC_KIND_BYTES);
        exact_empty.exact_empty_bytes = true;
        exact_empty.terminal_kind = Some(TerminalKind::DynamicBytes);
        let decoded = review_param_semantics(&exact_empty).expect("review semantics");
        assert!(decoded.contains("dynamicKind=bytes(0x02)"));
        assert!(decoded.contains("exactEmptyBytes=true"));

        let mut string_preimage = ParamSet::default();
        string_preimage.eip712_string_preimage_ordinal = Some(1);
        string_preimage.terminal_kind = Some(TerminalKind::Eip712StringHashWord);
        let decoded = review_param_semantics(&string_preimage).expect("review semantics");
        assert!(decoded.contains("eip712StringPreimageOrdinal=1"));
        assert!(decoded.contains("terminalKind=eip712StringHashWord(0x0a)"));
    }

    #[test]
    fn review_breakdown_records_emitted_intent_raw_tlv_and_decoded_interpolation() {
        let display: Display = serde_json::from_value(serde_json::json!({
            "formats": {
                "deposit(uint256 amount)": {
                    "intent": "Deposit collateral",
                    "interpolatedIntent": "Deposit {amount}",
                    "fields": [{
                    "path": "amount",
                    "label": "Amount",
                    "format": "amount"
                    }]
                }
            }
        }))
        .expect("synthetic display");
        let mut ctx = test_ctx();
        let (formats, pool) = compile_formats(&display, CTX_CONTRACT, &mut ctx, false)
            .expect("compile synthetic interpolation");
        let ir_bytes = build_ir(
            CTX_CONTRACT,
            1,
            [0x11; 20],
            &[0u8; 32],
            &ctx,
            &pool,
            &formats,
        )
        .expect("build synthetic IR");

        let (lines, fields, degraded) = review_field_breakdown(&ir_bytes);
        let review = lines.join("\n");
        assert_eq!((fields, degraded), (1, 0));
        assert!(review.contains(
            "format [0xb6b55f25] intent=\"Deposit collateral\" intent_raw=0x4465706f73697420636f6c6c61746572616c"
        ));
        assert!(review.contains("nested_descent_count=0 string_preimage_count=0"));
        assert!(review.contains("field[0] op=amount"));
        assert!(review.contains("label=\"Amount\" path=0x"));
        assert!(review.contains("params_tlv=0x"));
        assert!(review.contains(
            "interpolatedIntent={version=1,count=1,literals=[\"Deposit \",\"\"],ordinals=[0]}"
        ));
    }

    #[test]
    fn compiler_emits_authenticated_dynamic_string_kind() {
        let sig = "f(string value)";
        let parsed = parse_format_key(sig).unwrap();
        let field: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "value", "label": "Value", "format": "raw"
        }))
        .unwrap();
        let mut pool = Pool::new();
        let compiled = compile_one_field(
            sig,
            0,
            &field,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut pool,
            &BTreeMap::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_DYNAMIC_KIND),
            Some(&[DYNAMIC_KIND_STRING][..])
        );
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_TERMINAL_KIND),
            Some(&[TerminalKind::DynamicString as u8][..])
        );
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_INTEGER_WIDTH),
            None,
            "non-integer terminals must not carry an integer width"
        );
    }

    #[test]
    fn terminal_semantics_preserves_every_solidity_integer_width() {
        for width_bytes in 1u8..=32 {
            let bits = u16::from(width_bytes) * 8;
            for (prefix, kind) in [
                ("uint", TerminalKind::Unsigned),
                ("int", TerminalKind::Signed),
            ] {
                let ty = format!("{prefix}{bits}");
                assert_eq!(
                    terminal_semantics_from_type(&ty).unwrap(),
                    TerminalSemantics::integer(kind, width_bytes),
                    "width lowering drift for {ty}"
                );
                assert_eq!(
                    terminal_semantics_from_type(&format!("{ty}[]")).unwrap(),
                    TerminalSemantics::integer(kind, width_bytes),
                    "array element width lowering drift for {ty}[]"
                );
            }
        }

        assert_eq!(
            terminal_semantics_from_type("uint").unwrap(),
            TerminalSemantics::integer(TerminalKind::Unsigned, 32)
        );
        assert_eq!(
            terminal_semantics_from_type("int").unwrap(),
            TerminalSemantics::integer(TerminalKind::Signed, 32)
        );
        for invalid in [
            "uint0", "uint7", "uint08", "uint264", "int0", "int9", "int024", "int512",
        ] {
            assert!(
                terminal_semantics_from_type(invalid).is_err(),
                "invalid Solidity integer width accepted: {invalid}"
            );
        }
        for non_integer in ["address", "bool", "bytes4", "string", "bytes"] {
            assert_eq!(
                terminal_semantics_from_type(non_integer)
                    .unwrap()
                    .integer_width_bytes,
                None,
                "non-integer type gained an integer width: {non_integer}"
            );
        }
    }

    #[test]
    fn compiler_emits_integer_width_only_for_integer_fields_and_containers() {
        let cases = [
            ("f(uint8 value)", "value", CTX_CONTRACT, Some(1)),
            ("f(uint248 value)", "value", CTX_CONTRACT, Some(31)),
            ("f(uint256 value)", "value", CTX_CONTRACT, Some(32)),
            ("f(int24 value)", "value", CTX_CONTRACT, Some(3)),
            ("Order(int48 value)", "value", CTX_EIP712, Some(6)),
            ("f(uint16[] value)", "value.[]", CTX_CONTRACT, Some(2)),
            ("f(address value)", "value", CTX_CONTRACT, None),
            ("f(bytes4 value)", "value", CTX_CONTRACT, None),
        ];

        for (sig, path, context_kind, expected_width) in cases {
            let parsed = parse_format_key(sig).unwrap();
            let field: FieldDef = serde_json::from_value(serde_json::json!({
                "path": path, "label": "Value", "format": "raw"
            }))
            .unwrap();
            let mut pool = Pool::new();
            let compiled = compile_one_field(
                sig,
                0,
                &field,
                context_kind,
                &parsed,
                &mut test_ctx(),
                &mut pool,
                &BTreeMap::new(),
                false,
            )
            .unwrap();
            assert_eq!(
                find_tlv(&pool, compiled.param_off, PARAM_INTEGER_WIDTH),
                expected_width.as_ref().map(std::slice::from_ref),
                "wrong integer-width TLV for {sig} / {path}"
            );
        }

        let parsed = parse_format_key("f()").unwrap();
        for path in ["@.value", "@.chainId", "@.nonce"] {
            let field: FieldDef = serde_json::from_value(serde_json::json!({
                "path": path, "label": "Container", "format": "raw"
            }))
            .unwrap();
            let mut pool = Pool::new();
            let compiled = compile_one_field(
                "f()",
                0,
                &field,
                CTX_CONTRACT,
                &parsed,
                &mut test_ctx(),
                &mut pool,
                &BTreeMap::new(),
                false,
            )
            .unwrap();
            assert_eq!(
                find_tlv(&pool, compiled.param_off, PARAM_INTEGER_WIDTH),
                Some(&[32][..]),
                "container integer width must be uint256: {path}"
            );
        }

        for path in ["@.to", "@.from"] {
            let field: FieldDef = serde_json::from_value(serde_json::json!({
                "path": path, "label": "Container", "format": "raw"
            }))
            .unwrap();
            let mut pool = Pool::new();
            let compiled = compile_one_field(
                "f()",
                0,
                &field,
                CTX_CONTRACT,
                &parsed,
                &mut test_ctx(),
                &mut pool,
                &BTreeMap::new(),
                false,
            )
            .unwrap();
            assert_eq!(
                find_tlv(&pool, compiled.param_off, PARAM_INTEGER_WIDTH),
                None,
                "address container must not carry an integer width: {path}"
            );
        }
    }

    #[test]
    fn nested_eip712_elementary_fields_emit_integer_widths() {
        let sig = "Order(Meta details)Meta(uint48 nonce,int24 delta)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"details.nonce","label":"Nonce","format":"raw"},
              {"path":"details.delta","label":"Delta","format":"raw"}
            ]"#,
        );
        let mut pool = Pool::new();
        let (records, descents) = try_compile_eip712_nested(
            sig,
            &fmt,
            &parsed,
            &mut test_ctx(),
            &mut pool,
            &BTreeMap::new(),
            None,
        )
        .unwrap()
        .expect("supported nested scalar shape");
        assert_eq!(descents, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(
            find_tlv(&pool, records[0].param_off, PARAM_INTEGER_WIDTH),
            None,
            "nested anchor is not an integer"
        );

        let nested = find_tlv(&pool, records[0].param_off, PARAM_NESTED_STRUCT)
            .expect("nested anchor payload");
        assert_eq!(nested[0], 0x03);
        assert_eq!(u16::from_be_bytes([nested[35], nested[36]]), 2);
        let bitmap_len = 1usize;
        let mut cursor = 38 + bitmap_len;
        assert_eq!(nested[cursor], 2, "two nested elementary fields");
        cursor += 1;

        for (expected_kind, expected_width) in
            [(TerminalKind::Unsigned, 6u8), (TerminalKind::Signed, 3u8)]
        {
            let label_len = nested[cursor + 1] as usize;
            let param_at = cursor + 2 + label_len + 2;
            let param_off = u16::from_be_bytes([nested[param_at], nested[param_at + 1]]);
            assert_eq!(
                find_tlv(&pool, param_off, PARAM_TERMINAL_KIND),
                Some(&[expected_kind as u8][..])
            );
            assert_eq!(
                find_tlv(&pool, param_off, PARAM_INTEGER_WIDTH),
                Some(&[expected_width][..])
            );
            cursor += 2 + label_len + 4;
        }
        assert_eq!(
            cursor,
            nested.len(),
            "nested records consume payload exactly"
        );
    }

    #[test]
    fn compiler_rejects_formatter_terminal_mismatch_and_blank_visible_labels() {
        let sig = "f(address target,uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let bad_type: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "target", "label": "Target", "format": "amount"
        }))
        .unwrap();
        let error = compile_one_field(
            sig,
            0,
            &bad_type,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut Pool::new(),
            &BTreeMap::new(),
            false,
        )
        .expect_err("amount must not reinterpret an address terminal");
        assert!(error.contains("formatter/type/parameter policy"), "{error}");

        let blank: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "amount", "label": "   ", "format": "raw"
        }))
        .unwrap();
        let error = compile_one_field(
            sig,
            1,
            &blank,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut Pool::new(),
            &BTreeMap::new(),
            false,
        )
        .expect_err("visible labels must have a post-sanitization glyph");
        assert!(
            error.contains("empty post-sanitization visible label"),
            "{error}"
        );
    }

    #[test]
    fn nested_compiler_rejects_blank_visible_child_label() {
        let sig = "Order(Meta info,uint256 effect)Meta(uint256 amount)";
        let fmt = fmt_from_fields(
            r#"[
              {"path":"info.amount","label":"   ","format":"raw"},
              {"path":"effect","label":"Effect","format":"raw"}
            ]"#,
        );
        let mut out = Vec::new();
        let error = compile_one_format(
            sig,
            &fmt,
            CTX_EIP712,
            &mut test_ctx(),
            &mut Pool::new(),
            &BTreeMap::new(),
            &mut out,
            None,
        )
        .expect_err("nested visible child label must have a glyph");
        assert!(
            error.contains("empty post-sanitization visible label"),
            "{error}"
        );
    }

    #[test]
    fn enum_encoder_is_injective_after_device_canonicalization() {
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"0": "   "}),
            serde_json::json!({"0": "mode "}),
            serde_json::json!({"0": "same", "1": "same"}),
            // Each non-ASCII scalar sanitizes to the same printable `?`.
            serde_json::json!({"0": "α", "1": "β"}),
            serde_json::json!({
                "0": format!("{}A", "x".repeat(ENUM_DISPLAY_BYTES)),
                "1": format!("{}B", "x".repeat(ENUM_DISPLAY_BYTES))
            }),
        ] {
            assert!(encode_enum_table(&invalid).is_err(), "accepted {invalid}");
        }

        let valid = serde_json::json!({"0": "off", "1": "on"});
        let encoded = encode_enum_table(&valid).expect("injective enum encodes");
        pqsigner_erc7730::render::enums::validate_enum_table(&encoded, 0)
            .expect("device accepts compiler-canonical table");
    }

    #[test]
    fn compiler_omits_runtime_dead_opaque_bytes_format() {
        let sig = "f(bytes value)";
        let parsed = parse_format_key(sig).unwrap();
        let field: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "value", "label": "Value", "format": "raw"
        }))
        .unwrap();
        let err = compile_one_field(
            sig,
            0,
            &field,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut Pool::new(),
            &BTreeMap::new(),
            false,
        )
        .expect_err("opaque bytes have no injective runtime renderer");
        assert!(err.contains("hard-refuse every payload"), "got: {err}");
    }

    #[test]
    fn compiler_rejects_nonraw_dynamic_string() {
        let sig = "f(string value)";
        let parsed = parse_format_key(sig).unwrap();
        let field: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "value", "label": "Value", "format": "amount"
        }))
        .unwrap();
        let err = compile_one_field(
            sig,
            0,
            &field,
            CTX_CONTRACT,
            &parsed,
            &mut test_ctx(),
            &mut Pool::new(),
            &BTreeMap::new(),
            false,
        )
        .unwrap_err();
        assert!(err.contains("dynamic"), "unexpected error: {err}");
    }

    #[test]
    fn unit_base_constant_is_resolved_before_emission() {
        let sig = "f(uint256 value)";
        let parsed = parse_format_key(sig).unwrap();
        let field: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "value",
            "label": "Fee",
            "format": "unit",
            "params": { "base": "$.metadata.constants.feeUnit", "decimals": 0 }
        }))
        .unwrap();
        let mut ctx = test_ctx();
        ctx.constants
            .insert("feeUnit".into(), serde_json::json!("bps"));
        let mut pool = Pool::new();
        let compiled = compile_one_field(
            sig,
            0,
            &field,
            CTX_CONTRACT,
            &parsed,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            find_tlv(&pool, compiled.param_off, PARAM_BASE),
            Some(&b"bps"[..])
        );
    }

    #[test]
    fn signed_numeric_formatter_is_rejected_but_raw_is_allowed() {
        let sig = "f(int256 delta)";
        let parsed = parse_format_key(sig).unwrap();
        let mut ctx = test_ctx();
        let mut pool = Pool::new();
        let numeric: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "delta", "label": "Delta", "format": "unit",
            "params": { "base": "points" }
        }))
        .unwrap();
        let err = compile_one_field(
            sig,
            0,
            &numeric,
            CTX_CONTRACT,
            &parsed,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            false,
        )
        .unwrap_err();
        assert!(
            err.contains("numeric formatters are unsigned-only"),
            "{err}"
        );

        let raw: FieldDef = serde_json::from_value(serde_json::json!({
            "path": "delta", "label": "Delta", "format": "raw"
        }))
        .unwrap();
        assert!(compile_one_field(
            sig,
            0,
            &raw,
            CTX_CONTRACT,
            &parsed,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            false,
        )
        .is_ok());
    }

    #[test]
    fn unsupported_param_and_unit_prefix_fail_closed() {
        let sig = "f(uint256 value)";
        let parsed = parse_format_key(sig).unwrap();
        for params in [
            serde_json::json!({ "base": "bps", "mysteryScale": 10 }),
            serde_json::json!({ "base": "s", "prefix": true }),
        ] {
            let field: FieldDef = serde_json::from_value(serde_json::json!({
                "path": "value", "label": "Value", "format": "unit", "params": params
            }))
            .unwrap();
            let mut ctx = test_ctx();
            let mut pool = Pool::new();
            assert!(compile_one_field(
                sig,
                0,
                &field,
                CTX_CONTRACT,
                &parsed,
                &mut ctx,
                &mut pool,
                &BTreeMap::new(),
                false,
            )
            .is_err());
        }
    }

    #[test]
    fn constant_cannot_override_path_or_formatter_semantics() {
        let sig = "f(uint256 value)";
        let parsed = parse_format_key(sig).unwrap();
        for field_json in [
            serde_json::json!({
                "path": "value", "value": "benign", "label": "Value", "format": "raw"
            }),
            serde_json::json!({ "value": "benign", "label": "Value", "format": "amount" }),
        ] {
            let field: FieldDef = serde_json::from_value(field_json).unwrap();
            let mut ctx = test_ctx();
            let mut pool = Pool::new();
            assert!(compile_one_field(
                sig,
                0,
                &field,
                CTX_CONTRACT,
                &parsed,
                &mut ctx,
                &mut pool,
                &BTreeMap::new(),
                false,
            )
            .is_err());
        }
    }

    #[test]
    fn include_resolution_is_bounded_to_the_receipted_json_corpus() {
        let temp = tempfile::tempdir().expect("create registry fixture");
        let root = temp.path();
        let registry_dir = root.join("registry/example");
        let ercs_dir = root.join("ercs");
        fs::create_dir_all(&registry_dir).unwrap();
        fs::create_dir_all(&ercs_dir).unwrap();
        let descriptor = registry_dir.join("descriptor.json");
        fs::write(&descriptor, b"{}\n").unwrap();
        fs::write(registry_dir.join("common.json"), b"{}\n").unwrap();
        fs::write(ercs_dir.join("base.json"), b"{}\n").unwrap();

        assert_eq!(
            resolve_include_path(root, &descriptor, "common.json").unwrap(),
            registry_dir.join("common.json").canonicalize().unwrap()
        );
        assert_eq!(
            resolve_include_path(root, &descriptor, "../../ercs/base.json").unwrap(),
            ercs_dir.join("base.json").canonicalize().unwrap()
        );

        fs::write(root.join("planted.json"), b"{}\n").unwrap();
        let error = resolve_include_path(root, &descriptor, "../../planted.json").unwrap_err();
        assert!(error.contains("outside the receipted"), "{error}");

        for (relative, include_ref) in [
            ("registry/example/common.txt", "common.txt"),
            ("registry/example/hidden.tests.json", "hidden.tests.json"),
            ("registry/example/tests/hidden.json", "tests/hidden.json"),
        ] {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"{}\n").unwrap();
            let error = resolve_include_path(root, &descriptor, include_ref).unwrap_err();
            assert!(error.contains("outside the receipted"), "{error}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(
                registry_dir.join("common.json"),
                registry_dir.join("link.json"),
            )
            .unwrap();
            let error = resolve_include_path(root, &descriptor, "link.json").unwrap_err();
            assert!(error.contains("non-symlink"), "{error}");
        }
    }
}
