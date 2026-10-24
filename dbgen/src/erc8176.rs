//! Offline, fail-closed verification of ERC-8176 EAS-v2 descriptor attestations.
//!
//! This module is deliberately host-only. It accepts a bounded, versioned JSON
//! snapshot and an independently supplied [`SnapshotAnchor`]. The snapshot is
//! useful only after all of the following bind to the same Ethereum checkpoint:
//!
//! - the raw snapshot SHA-256 and full block-header Keccak hash;
//! - the header's block number, timestamp, and state root;
//! - the canonical mainnet EAS account and its exact runtime code hash;
//! - every recovered EOA attester and every off-chain-revocation storage slot;
//! - the exact ERC-8176 descriptor hash signed in EAS-v2 typed data.
//!
//! It performs no network access. In particular, an RPC/GraphQL response or a
//! self-declared `revoked: false` bit is never evidence here: account and
//! storage Merkle-Patricia proofs are checked against the authenticated header.

use crate::eip1186::{verify_account_proof, verify_storage_proof};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use pqsigner_tx_core::hash::keccak256;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Snapshot schema owned by this verifier. Changes require a new format ID.
pub const SNAPSHOT_FORMAT_V1: &str = "pqsigner-erc8176-eas-snapshot-v1";
/// Exact draft reviewed for this implementation.
pub const ERC8176_DRAFT_COMMIT: &str = "502c96345b630b66e1dc7d8c790831c7cc2478eb";
pub const EAS_CHAIN_ID: u64 = 1;
pub const EAS_OFFCHAIN_VERSION: u16 = 2;
pub const EAS_DOMAIN_NAME: &str = "EAS Attestation";
pub const EAS_DOMAIN_VERSION: &str = "0.26";
pub const EAS_CONTRACT: [u8; 20] = [
    0xa1, 0x20, 0x7f, 0x3b, 0xba, 0x22, 0x4e, 0x2c, 0x9c, 0x3c, 0x6d, 0x5a, 0xf6, 0x3d, 0x0e, 0xb1,
    0x58, 0x2c, 0xe5, 0x87,
];
pub const ERC8176_SCHEMA_UID: [u8; 32] = [
    0xe0, 0x23, 0xee, 0xf1, 0x13, 0xc1, 0x67, 0x07, 0x74, 0x80, 0x1c, 0x34, 0xb3, 0x77, 0xfd, 0xf6,
    0x12, 0xdd, 0x8a, 0x4d, 0x2f, 0xa9, 0x2f, 0xe3, 0x82, 0xe1, 0x5b, 0xd9, 0x1f, 0xaf, 0xb5, 0xc2,
];
/// `keccak256(runtime bytecode)` of the canonical EAS 0.26 mainnet deployment.
pub const EAS_RUNTIME_CODE_HASH: [u8; 32] = [
    0xf2, 0x7d, 0xe0, 0xb2, 0x83, 0x7e, 0xa2, 0xbd, 0xdd, 0x91, 0x2c, 0x75, 0x69, 0x43, 0x33, 0xc8,
    0x22, 0xe6, 0xa5, 0x42, 0x15, 0xda, 0xff, 0xdf, 0xfd, 0xb0, 0xf5, 0x7c, 0x6e, 0x42, 0x3c, 0xa0,
];
/// Solidity storage slot of EAS 0.26 `_revocationsOffchain`.
pub const EAS_OFFCHAIN_REVOCATIONS_SLOT: u64 = 3;

pub const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ATTESTATIONS: usize = 4096;
pub const MAX_SIGNER_WITNESSES: usize = 512;
pub const MAX_TRUSTED_ATTESTERS: usize = 512;
pub const MAX_PROOF_NODES: usize = 65;
pub const MAX_PROOF_NODE_BYTES: usize = 1024;
pub const MAX_DECODED_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BLOCK_HEADER_BYTES: usize = 2048;

const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// Release-owned facts which are intentionally not trusted from the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAnchor {
    pub snapshot_sha256: [u8; 32],
    pub checkpoint_block_hash: [u8; 32],
    pub checkpoint_block_number: u64,
    pub evaluation_timestamp: u64,
    pub max_checkpoint_age_seconds: u64,
    pub min_remaining_validity_seconds: u64,
}

/// Immutable result consumed by catalogue admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestationSet {
    by_descriptor: BTreeMap<[u8; 32], BTreeSet<[u8; 20]>>,
    trusted_attesters: BTreeSet<[u8; 20]>,
    snapshot_sha256: [u8; 32],
    checkpoint_block_hash: [u8; 32],
    checkpoint_block_number: u64,
    checkpoint_timestamp: u64,
    evaluation_timestamp: u64,
    max_checkpoint_age_seconds: u64,
    min_remaining_validity_seconds: u64,
    attestation_count: usize,
}

impl VerifiedAttestationSet {
    #[must_use]
    pub fn attester_count(&self, descriptor_hash: [u8; 32]) -> usize {
        self.by_descriptor
            .get(&descriptor_hash)
            .map_or(0, BTreeSet::len)
    }

    #[must_use]
    pub fn attesters(&self, descriptor_hash: [u8; 32]) -> Option<&BTreeSet<[u8; 20]>> {
        self.by_descriptor.get(&descriptor_hash)
    }

    #[must_use]
    pub fn trusted_attesters(&self) -> &BTreeSet<[u8; 20]> {
        &self.trusted_attesters
    }

    #[must_use]
    pub fn snapshot_sha256(&self) -> [u8; 32] {
        self.snapshot_sha256
    }

    #[must_use]
    pub fn checkpoint_block_hash(&self) -> [u8; 32] {
        self.checkpoint_block_hash
    }

    #[must_use]
    pub fn checkpoint_block_number(&self) -> u64 {
        self.checkpoint_block_number
    }

    #[must_use]
    pub fn checkpoint_timestamp(&self) -> u64 {
        self.checkpoint_timestamp
    }

    #[must_use]
    pub fn evaluation_timestamp(&self) -> u64 {
        self.evaluation_timestamp
    }

    #[must_use]
    pub fn max_checkpoint_age_seconds(&self) -> u64 {
        self.max_checkpoint_age_seconds
    }

    #[must_use]
    pub fn min_remaining_validity_seconds(&self) -> u64 {
        self.min_remaining_validity_seconds
    }

    #[must_use]
    pub fn attestation_count(&self) -> usize {
        self.attestation_count
    }

    #[must_use]
    pub fn descriptor_count(&self) -> usize {
        self.by_descriptor.len()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotV1 {
    format: String,
    draft_commit: String,
    chain_id: u64,
    eas_contract: String,
    eas_runtime_code_hash: String,
    block_header_rlp: String,
    eas_account_proof: Vec<String>,
    signer_accounts: Vec<SignerAccountWitness>,
    attestations: Vec<AttestationRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerAccountWitness {
    address: String,
    account_proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationRecord {
    uid: String,
    version: u16,
    schema: String,
    recipient: String,
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: String,
    data: String,
    salt: String,
    attester: String,
    signature: EcdsaSignature,
    revocation_proof: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EcdsaSignature {
    r: String,
    s: String,
    v: u8,
}

/// Read a deterministic regular file and verify it without any network access.
pub fn load_and_verify_snapshot(
    path: &Path,
    anchor: &SnapshotAnchor,
    trusted_attesters: &BTreeSet<[u8; 20]>,
) -> Result<VerifiedAttestationSet, String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| format!("stat ERC-8176 snapshot {}: {error}", path.display()))?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        return Err(format!(
            "ERC-8176 snapshot {} must be a non-symlink regular file",
            path.display()
        ));
    }
    if before.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "ERC-8176 snapshot {} is {} bytes; cap is {MAX_SNAPSHOT_BYTES}",
            path.display(),
            before.len()
        ));
    }

    let file = File::open(path)
        .map_err(|error| format!("open ERC-8176 snapshot {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("fstat ERC-8176 snapshot {}: {error}", path.display()))?;
    if !after.file_type().is_file() {
        return Err(format!(
            "ERC-8176 snapshot {} changed to a non-regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(format!(
                "ERC-8176 snapshot {} changed between stat and open",
                path.display()
            ));
        }
    }

    let initial_capacity = usize::try_from(after.len())
        .unwrap_or(usize::MAX)
        .min(MAX_SNAPSHOT_BYTES as usize);
    let mut raw = Vec::with_capacity(initial_capacity);
    file.take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("read ERC-8176 snapshot {}: {error}", path.display()))?;
    if raw.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "ERC-8176 snapshot {} grew beyond {MAX_SNAPSHOT_BYTES} bytes",
            path.display()
        ));
    }
    verify_snapshot_bytes(&raw, anchor, trusted_attesters)
}

/// Verify already-loaded snapshot bytes. This is also the deterministic test API.
pub fn verify_snapshot_bytes(
    raw: &[u8],
    anchor: &SnapshotAnchor,
    trusted_attesters: &BTreeSet<[u8; 20]>,
) -> Result<VerifiedAttestationSet, String> {
    if raw.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "ERC-8176 snapshot is {} bytes; cap is {MAX_SNAPSHOT_BYTES}",
            raw.len()
        ));
    }
    if raw.is_empty() {
        return Err("ERC-8176 snapshot is empty".to_string());
    }
    let snapshot_sha256 = sha256(raw);
    if snapshot_sha256 != anchor.snapshot_sha256 {
        return Err(format!(
            "ERC-8176 snapshot SHA-256 mismatch: expected 0x{}, got 0x{}",
            hex::encode(anchor.snapshot_sha256),
            hex::encode(snapshot_sha256)
        ));
    }
    validate_trusted_set(trusted_attesters)?;
    reject_duplicate_json_keys(raw)?;
    let snapshot: SnapshotV1 = serde_json::from_slice(raw)
        .map_err(|error| format!("parse ERC-8176 snapshot JSON: {error}"))?;

    if snapshot.format != SNAPSHOT_FORMAT_V1 {
        return Err(format!(
            "unsupported ERC-8176 snapshot format {:?}; expected {SNAPSHOT_FORMAT_V1:?}",
            snapshot.format
        ));
    }
    if snapshot.draft_commit != ERC8176_DRAFT_COMMIT {
        return Err(format!(
            "ERC-8176 draft commit mismatch: expected {ERC8176_DRAFT_COMMIT}, got {}",
            snapshot.draft_commit
        ));
    }
    if snapshot.chain_id != EAS_CHAIN_ID {
        return Err(format!(
            "ERC-8176 snapshot chain_id must be {EAS_CHAIN_ID}, got {}",
            snapshot.chain_id
        ));
    }
    require_hex_exact::<20>("eas_contract", &snapshot.eas_contract, EAS_CONTRACT)?;
    require_hex_exact::<32>(
        "eas_runtime_code_hash",
        &snapshot.eas_runtime_code_hash,
        EAS_RUNTIME_CODE_HASH,
    )?;
    if snapshot.attestations.len() > MAX_ATTESTATIONS {
        return Err(format!(
            "ERC-8176 snapshot has {} attestations; cap is {MAX_ATTESTATIONS}",
            snapshot.attestations.len()
        ));
    }
    if snapshot.signer_accounts.len() > MAX_SIGNER_WITNESSES {
        return Err(format!(
            "ERC-8176 snapshot has {} signer witnesses; cap is {MAX_SIGNER_WITNESSES}",
            snapshot.signer_accounts.len()
        ));
    }

    let header_rlp = decode_hex_bounded(
        "block_header_rlp",
        &snapshot.block_header_rlp,
        MAX_BLOCK_HEADER_BYTES,
    )?;
    let block_hash = keccak256(&header_rlp);
    if block_hash != anchor.checkpoint_block_hash {
        return Err(format!(
            "checkpoint block hash mismatch: expected 0x{}, got 0x{}",
            hex::encode(anchor.checkpoint_block_hash),
            hex::encode(block_hash)
        ));
    }
    let header = parse_mainnet_header(&header_rlp)?;
    if header.number != anchor.checkpoint_block_number {
        return Err(format!(
            "checkpoint block number mismatch: expected {}, got {}",
            anchor.checkpoint_block_number, header.number
        ));
    }
    if header.timestamp > anchor.evaluation_timestamp {
        return Err(format!(
            "checkpoint timestamp {} is after evaluation timestamp {}",
            header.timestamp, anchor.evaluation_timestamp
        ));
    }
    let checkpoint_age = anchor.evaluation_timestamp - header.timestamp;
    if checkpoint_age > anchor.max_checkpoint_age_seconds {
        return Err(format!(
            "checkpoint is {checkpoint_age}s old at evaluation; freshness cap is {}s",
            anchor.max_checkpoint_age_seconds
        ));
    }
    let minimum_expiry = anchor
        .evaluation_timestamp
        .checked_add(anchor.min_remaining_validity_seconds)
        .ok_or_else(|| "evaluation timestamp + minimum validity overflows u64".to_string())?;

    let mut decoded_proof_bytes = 0usize;
    let eas_account_proof = decode_proof(
        "eas_account_proof",
        &snapshot.eas_account_proof,
        &mut decoded_proof_bytes,
    )?;
    let eas_account = verify_account_proof(header.state_root, EAS_CONTRACT, &eas_account_proof)
        .map_err(|error| format!("verify EAS account proof: {error}"))?
        .ok_or_else(|| "canonical EAS account is absent at checkpoint".to_string())?;
    if eas_account.code_hash != EAS_RUNTIME_CODE_HASH {
        return Err(format!(
            "EAS runtime code hash mismatch in account proof: expected 0x{}, got 0x{}",
            hex::encode(EAS_RUNTIME_CODE_HASH),
            hex::encode(eas_account.code_hash)
        ));
    }

    let mut signer_witnesses = BTreeMap::<[u8; 20], Vec<Vec<u8>>>::new();
    for (index, witness) in snapshot.signer_accounts.iter().enumerate() {
        let address = decode_hex_exact::<20>(
            &format!("signer_accounts[{index}].address"),
            &witness.address,
        )?;
        let proof = decode_proof(
            &format!("signer_accounts[{index}].account_proof"),
            &witness.account_proof,
            &mut decoded_proof_bytes,
        )?;
        if signer_witnesses.insert(address, proof).is_some() {
            return Err(format!(
                "duplicate signer account witness for 0x{}",
                hex::encode(address)
            ));
        }
    }

    let mut by_descriptor = BTreeMap::<[u8; 32], BTreeSet<[u8; 20]>>::new();
    let mut used_witnesses = BTreeSet::<[u8; 20]>::new();
    let mut seen_attester_uids = BTreeSet::<([u8; 20], [u8; 32])>::new();
    let mut seen_descriptor_attesters = BTreeSet::<([u8; 32], [u8; 20])>::new();

    for (index, record) in snapshot.attestations.iter().enumerate() {
        let label = format!("attestations[{index}]");
        if record.version != EAS_OFFCHAIN_VERSION {
            return Err(format!(
                "{label}.version must be {EAS_OFFCHAIN_VERSION}, got {}",
                record.version
            ));
        }
        let schema = decode_hex_exact::<32>(&format!("{label}.schema"), &record.schema)?;
        if schema != ERC8176_SCHEMA_UID {
            return Err(format!(
                "{label}.schema is not the pinned ERC-8176 schema UID"
            ));
        }
        let recipient = decode_hex_exact::<20>(&format!("{label}.recipient"), &record.recipient)?;
        if recipient != [0; 20] {
            return Err(format!("{label}.recipient must be the zero address"));
        }
        let ref_uid = decode_hex_exact::<32>(&format!("{label}.ref_uid"), &record.ref_uid)?;
        if ref_uid != [0; 32] {
            return Err(format!("{label}.ref_uid must be zero"));
        }
        if !record.revocable {
            return Err(format!("{label}.revocable must be true"));
        }
        if record.time == 0 || record.time > header.timestamp {
            return Err(format!(
                "{label}.time must be nonzero and no later than checkpoint timestamp {}",
                header.timestamp
            ));
        }
        validate_expiration(
            &label,
            record.expiration_time,
            anchor.evaluation_timestamp,
            minimum_expiry,
        )?;

        let descriptor_hash = decode_hex_exact::<32>(&format!("{label}.data"), &record.data)?;
        let salt = decode_hex_exact::<32>(&format!("{label}.salt"), &record.salt)?;
        let uid = decode_hex_exact::<32>(&format!("{label}.uid"), &record.uid)?;
        let message = EasV2Message {
            schema,
            recipient,
            time: record.time,
            expiration_time: record.expiration_time,
            revocable: record.revocable,
            ref_uid,
            data: descriptor_hash,
            salt,
        };
        let expected_uid = eas_v2_uid(&message);
        if uid != expected_uid {
            return Err(format!(
                "{label}.uid mismatch: expected 0x{}, got 0x{}",
                hex::encode(expected_uid),
                hex::encode(uid)
            ));
        }
        let digest = eas_v2_typed_data_digest(&message);
        let r = decode_hex_exact::<32>(&format!("{label}.signature.r"), &record.signature.r)?;
        let s = decode_hex_exact::<32>(&format!("{label}.signature.s"), &record.signature.s)?;
        let recovered = recover_eoa(digest, r, s, record.signature.v)
            .map_err(|error| format!("{label}.signature: {error}"))?;
        let claimed_attester =
            decode_hex_exact::<20>(&format!("{label}.attester"), &record.attester)?;
        if recovered != claimed_attester {
            return Err(format!(
                "{label}.attester mismatch: signature recovered 0x{}, record claims 0x{}",
                hex::encode(recovered),
                hex::encode(claimed_attester)
            ));
        }
        if !trusted_attesters.contains(&recovered) {
            return Err(format!(
                "{label}.attester 0x{} is not in the independently supplied trust set",
                hex::encode(recovered)
            ));
        }
        if !seen_attester_uids.insert((recovered, uid)) {
            return Err(format!(
                "{label}.uid duplicates an earlier attestation from the same signer"
            ));
        }

        let signer_proof = signer_witnesses.get(&recovered).ok_or_else(|| {
            format!(
                "{label} has no account proof for recovered attester 0x{}",
                hex::encode(recovered)
            )
        })?;
        match verify_account_proof(header.state_root, recovered, signer_proof)
            .map_err(|error| format!("verify {label} signer account proof: {error}"))?
        {
            None => {}
            Some(account) if account.code_hash == EMPTY_CODE_HASH => {}
            Some(account) => {
                return Err(format!(
                    "{label}.attester 0x{} is a contract at checkpoint (code hash 0x{}); v1 supports EOA/absent signers only",
                    hex::encode(recovered),
                    hex::encode(account.code_hash)
                ));
            }
        }
        used_witnesses.insert(recovered);

        let revocation_proof = decode_proof(
            &format!("{label}.revocation_proof"),
            &record.revocation_proof,
            &mut decoded_proof_bytes,
        )?;
        let revocation_slot = eas_offchain_revocation_slot(recovered, uid);
        let revocation =
            verify_storage_proof(eas_account.storage_root, revocation_slot, &revocation_proof)
                .map_err(|error| format!("verify {label} revocation proof: {error}"))?;
        if let Some(value) = revocation {
            return Err(format!(
                "{label} is revoked at checkpoint (storage value 0x{})",
                hex::encode(value)
            ));
        }

        if !seen_descriptor_attesters.insert((descriptor_hash, recovered)) {
            return Err(format!(
                "{label} duplicates descriptor 0x{} / attester 0x{}",
                hex::encode(descriptor_hash),
                hex::encode(recovered)
            ));
        }
        by_descriptor
            .entry(descriptor_hash)
            .or_default()
            .insert(recovered);
    }

    let supplied_witnesses: BTreeSet<[u8; 20]> = signer_witnesses.keys().copied().collect();
    if used_witnesses != supplied_witnesses {
        let unused: Vec<String> = supplied_witnesses
            .difference(&used_witnesses)
            .map(|address| format!("0x{}", hex::encode(address)))
            .collect();
        return Err(format!(
            "snapshot contains unused signer account witnesses: {}",
            unused.join(", ")
        ));
    }

    Ok(VerifiedAttestationSet {
        by_descriptor,
        trusted_attesters: trusted_attesters.clone(),
        snapshot_sha256,
        checkpoint_block_hash: block_hash,
        checkpoint_block_number: header.number,
        checkpoint_timestamp: header.timestamp,
        evaluation_timestamp: anchor.evaluation_timestamp,
        max_checkpoint_age_seconds: anchor.max_checkpoint_age_seconds,
        min_remaining_validity_seconds: anchor.min_remaining_validity_seconds,
        attestation_count: snapshot.attestations.len(),
    })
}

fn validate_trusted_set(trusted: &BTreeSet<[u8; 20]>) -> Result<(), String> {
    if trusted.is_empty() {
        return Err("ERC-8176 trusted-attester set is empty".to_string());
    }
    if trusted.len() > MAX_TRUSTED_ATTESTERS {
        return Err(format!(
            "ERC-8176 trusted-attester set has {} entries; cap is {MAX_TRUSTED_ATTESTERS}",
            trusted.len()
        ));
    }
    if trusted.contains(&[0; 20]) {
        return Err("ERC-8176 trusted-attester set contains the zero address".to_string());
    }
    Ok(())
}

fn validate_expiration(
    label: &str,
    expiration_time: u64,
    evaluation_timestamp: u64,
    minimum_expiry: u64,
) -> Result<(), String> {
    if expiration_time != 0
        && (expiration_time <= evaluation_timestamp || expiration_time < minimum_expiry)
    {
        return Err(format!(
            "{label}.expiration_time must be zero (no expiration) or unexpired with at least the anchored validity margin (minimum {minimum_expiry})"
        ));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = [0; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn require_hex_exact<const N: usize>(
    label: &str,
    encoded: &str,
    expected: [u8; N],
) -> Result<(), String> {
    let actual = decode_hex_exact::<N>(label, encoded)?;
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected 0x{}, got 0x{}",
            hex::encode(expected),
            hex::encode(actual)
        ));
    }
    Ok(())
}

fn decode_hex_exact<const N: usize>(label: &str, encoded: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex_bounded(label, encoded, N)?;
    if bytes.len() != N {
        return Err(format!(
            "{label} must encode exactly {N} bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_bounded(label: &str, encoded: &str, cap: usize) -> Result<Vec<u8>, String> {
    let body = encoded
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} must use a lowercase 0x prefix"))?;
    if body.len() % 2 != 0 {
        return Err(format!("{label} must contain an even number of hex digits"));
    }
    if body.len() / 2 > cap {
        return Err(format!(
            "{label} decodes to {} bytes; cap is {cap}",
            body.len() / 2
        ));
    }
    if !body
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!("{label} must contain canonical lowercase hex"));
    }
    hex::decode(body).map_err(|error| format!("decode {label}: {error}"))
}

fn decode_proof(
    label: &str,
    encoded: &[String],
    decoded_total: &mut usize,
) -> Result<Vec<Vec<u8>>, String> {
    if encoded.len() > MAX_PROOF_NODES {
        return Err(format!(
            "{label} must contain 0..={MAX_PROOF_NODES} proof nodes, got {}",
            encoded.len()
        ));
    }
    let mut proof = Vec::with_capacity(encoded.len());
    for (index, node) in encoded.iter().enumerate() {
        let decoded = decode_hex_bounded(&format!("{label}[{index}]"), node, MAX_PROOF_NODE_BYTES)?;
        if decoded.is_empty() {
            return Err(format!("{label}[{index}] is empty"));
        }
        *decoded_total = decoded_total
            .checked_add(decoded.len())
            .ok_or_else(|| "decoded proof byte count overflow".to_string())?;
        if *decoded_total > MAX_DECODED_PROOF_BYTES {
            return Err(format!(
                "decoded proof material exceeds {MAX_DECODED_PROOF_BYTES} bytes"
            ));
        }
        proof.push(decoded);
    }
    Ok(proof)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockHeader {
    state_root: [u8; 32],
    number: u64,
    timestamp: u64,
}

#[derive(Clone, Copy)]
struct RlpItem<'a> {
    is_list: bool,
    payload: &'a [u8],
    encoded_len: usize,
}

fn parse_mainnet_header(encoded: &[u8]) -> Result<BlockHeader, String> {
    let top = parse_rlp_item(encoded)?;
    if !top.is_list || top.encoded_len != encoded.len() {
        return Err("block_header_rlp must be exactly one RLP list".to_string());
    }
    let mut fields = Vec::new();
    let mut rest = top.payload;
    while !rest.is_empty() {
        let item = parse_rlp_item(rest)?;
        if item.is_list {
            return Err("block header fields must be RLP byte strings".to_string());
        }
        fields.push(item.payload);
        rest = &rest[item.encoded_len..];
    }
    // Mainnet Pectra execution headers contain the original 15 fields plus
    // baseFee, withdrawalsRoot, the two blob-gas scalars,
    // parentBeaconBlockRoot, and requestsHash. A future fork changes the
    // authenticated format and must introduce a new snapshot version.
    if fields.len() != 21 {
        return Err(format!(
            "snapshot-v1 requires a 21-field mainnet Pectra header, got {} fields",
            fields.len()
        ));
    }
    require_rlp_len("parentHash", fields[0], 32)?;
    require_rlp_len("ommersHash", fields[1], 32)?;
    require_rlp_len("beneficiary", fields[2], 20)?;
    require_rlp_len("stateRoot", fields[3], 32)?;
    require_rlp_len("transactionsRoot", fields[4], 32)?;
    require_rlp_len("receiptsRoot", fields[5], 32)?;
    require_rlp_len("logsBloom", fields[6], 256)?;
    validate_rlp_scalar("difficulty", fields[7], 32)?;
    let number = parse_rlp_u64("number", fields[8])?;
    parse_rlp_u64("gasLimit", fields[9])?;
    parse_rlp_u64("gasUsed", fields[10])?;
    let timestamp = parse_rlp_u64("timestamp", fields[11])?;
    if fields[12].len() > 32 {
        return Err("block header extraData exceeds 32 bytes".to_string());
    }
    require_rlp_len("prevRandao", fields[13], 32)?;
    require_rlp_len("nonce", fields[14], 8)?;
    validate_rlp_scalar("baseFeePerGas", fields[15], 32)?;
    require_rlp_len("withdrawalsRoot", fields[16], 32)?;
    parse_rlp_u64("blobGasUsed", fields[17])?;
    parse_rlp_u64("excessBlobGas", fields[18])?;
    require_rlp_len("parentBeaconBlockRoot", fields[19], 32)?;
    require_rlp_len("requestsHash", fields[20], 32)?;

    let mut state_root = [0; 32];
    state_root.copy_from_slice(fields[3]);
    Ok(BlockHeader {
        state_root,
        number,
        timestamp,
    })
}

fn require_rlp_len(label: &str, bytes: &[u8], expected: usize) -> Result<(), String> {
    if bytes.len() != expected {
        return Err(format!(
            "block header {label} must be {expected} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(())
}

fn validate_rlp_scalar(label: &str, bytes: &[u8], max_len: usize) -> Result<(), String> {
    if bytes.len() > max_len {
        return Err(format!(
            "block header {label} exceeds its {max_len}-byte scalar bound"
        ));
    }
    if bytes.first() == Some(&0) {
        return Err(format!(
            "block header {label} is not a canonical RLP integer"
        ));
    }
    Ok(())
}

fn parse_rlp_u64(label: &str, bytes: &[u8]) -> Result<u64, String> {
    validate_rlp_scalar(label, bytes, 8)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn parse_rlp_item(input: &[u8]) -> Result<RlpItem<'_>, String> {
    let first = *input
        .first()
        .ok_or_else(|| "truncated RLP item".to_string())?;
    match first {
        0x00..=0x7f => Ok(RlpItem {
            is_list: false,
            payload: &input[..1],
            encoded_len: 1,
        }),
        0x80..=0xb7 => {
            let length = usize::from(first - 0x80);
            let end = 1usize
                .checked_add(length)
                .ok_or_else(|| "RLP string length overflow".to_string())?;
            if end > input.len() {
                return Err("truncated short RLP string".to_string());
            }
            if length == 1 && input[1] <= 0x7f {
                return Err("non-canonical single-byte RLP string".to_string());
            }
            Ok(RlpItem {
                is_list: false,
                payload: &input[1..end],
                encoded_len: end,
            })
        }
        0xb8..=0xbf => parse_long_rlp_item(input, false, usize::from(first - 0xb7)),
        0xc0..=0xf7 => {
            let length = usize::from(first - 0xc0);
            let end = 1usize
                .checked_add(length)
                .ok_or_else(|| "RLP list length overflow".to_string())?;
            if end > input.len() {
                return Err("truncated short RLP list".to_string());
            }
            Ok(RlpItem {
                is_list: true,
                payload: &input[1..end],
                encoded_len: end,
            })
        }
        0xf8..=0xff => parse_long_rlp_item(input, true, usize::from(first - 0xf7)),
    }
}

fn parse_long_rlp_item(
    input: &[u8],
    is_list: bool,
    length_of_length: usize,
) -> Result<RlpItem<'_>, String> {
    if length_of_length == 0 || length_of_length > core::mem::size_of::<usize>() {
        return Err("unsupported RLP length-of-length".to_string());
    }
    let prefix_end = 1usize
        .checked_add(length_of_length)
        .ok_or_else(|| "RLP prefix length overflow".to_string())?;
    if prefix_end > input.len() {
        return Err("truncated long RLP length".to_string());
    }
    if input[1] == 0 {
        return Err("non-canonical RLP length with a leading zero".to_string());
    }
    let mut length = 0usize;
    for byte in &input[1..prefix_end] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or_else(|| "RLP payload length overflow".to_string())?;
    }
    if length < 56 {
        return Err("non-canonical long RLP item shorter than 56 bytes".to_string());
    }
    let end = prefix_end
        .checked_add(length)
        .ok_or_else(|| "RLP item length overflow".to_string())?;
    if end > input.len() {
        return Err("truncated long RLP payload".to_string());
    }
    Ok(RlpItem {
        is_list,
        payload: &input[prefix_end..end],
        encoded_len: end,
    })
}

#[derive(Clone, Copy)]
struct EasV2Message {
    schema: [u8; 32],
    recipient: [u8; 20],
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: [u8; 32],
    data: [u8; 32],
    salt: [u8; 32],
}

fn eas_v2_typed_data_digest(message_fields: &EasV2Message) -> [u8; 32] {
    let domain_type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut domain = Vec::with_capacity(32 * 5);
    domain.extend_from_slice(&domain_type_hash);
    domain.extend_from_slice(&keccak256(EAS_DOMAIN_NAME.as_bytes()));
    domain.extend_from_slice(&keccak256(EAS_DOMAIN_VERSION.as_bytes()));
    domain.extend_from_slice(&u256_word(EAS_CHAIN_ID));
    domain.extend_from_slice(&address_word(EAS_CONTRACT));
    let domain_separator = keccak256(&domain);

    let attest_type_hash = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)",
    );
    let mut message = Vec::with_capacity(32 * 10);
    message.extend_from_slice(&attest_type_hash);
    message.extend_from_slice(&u256_word(u64::from(EAS_OFFCHAIN_VERSION)));
    message.extend_from_slice(&message_fields.schema);
    message.extend_from_slice(&address_word(message_fields.recipient));
    message.extend_from_slice(&u256_word(message_fields.time));
    message.extend_from_slice(&u256_word(message_fields.expiration_time));
    message.extend_from_slice(&u256_word(u64::from(message_fields.revocable)));
    message.extend_from_slice(&message_fields.ref_uid);
    message.extend_from_slice(&keccak256(&message_fields.data));
    message.extend_from_slice(&message_fields.salt);
    let struct_hash = keccak256(&message);

    let mut digest = [0u8; 66];
    digest[0] = 0x19;
    digest[1] = 0x01;
    digest[2..34].copy_from_slice(&domain_separator);
    digest[34..].copy_from_slice(&struct_hash);
    keccak256(&digest)
}

fn eas_v2_uid(message: &EasV2Message) -> [u8; 32] {
    debug_assert_eq!(message.schema, ERC8176_SCHEMA_UID);
    // EAS SDK Offchain v2 `getUID`: uint16 version, the UTF-8 bytes of the
    // canonical `0x` schema string, recipient, zero attester, uint64 times,
    // bool, bytes32 refUID, dynamic bytes data, bytes32 salt, uint32 bump=0.
    let mut packed = Vec::with_capacity(2 + 66 + 20 + 20 + 8 + 8 + 1 + 32 + 32 + 32 + 4);
    packed.extend_from_slice(&EAS_OFFCHAIN_VERSION.to_be_bytes());
    packed.extend_from_slice(b"0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2");
    packed.extend_from_slice(&message.recipient);
    packed.extend_from_slice(&[0; 20]);
    packed.extend_from_slice(&message.time.to_be_bytes());
    packed.extend_from_slice(&message.expiration_time.to_be_bytes());
    packed.push(u8::from(message.revocable));
    packed.extend_from_slice(&message.ref_uid);
    packed.extend_from_slice(&message.data);
    packed.extend_from_slice(&message.salt);
    packed.extend_from_slice(&0u32.to_be_bytes());
    keccak256(&packed)
}

fn recover_eoa(digest: [u8; 32], r: [u8; 32], s: [u8; 32], v: u8) -> Result<[u8; 20], String> {
    let recovery_byte = v
        .checked_sub(27)
        .filter(|value| *value <= 1)
        .ok_or_else(|| format!("v must be canonical 27 or 28, got {v}"))?;
    let signature = Signature::from_scalars(r, s)
        .map_err(|error| format!("invalid secp256k1 r/s scalars: {error}"))?;
    if signature.normalize_s() != signature {
        return Err("high-s secp256k1 signature is non-canonical".to_string());
    }
    let recovery_id = RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| format!("invalid secp256k1 recovery id {recovery_byte}"))?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|error| format!("secp256k1 recovery failed: {error}"))?;
    let encoded = key.to_sec1_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err("recovered secp256k1 key is not uncompressed SEC1".to_string());
    }
    let hash = keccak256(&bytes[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

fn eas_offchain_revocation_slot(attester: [u8; 20], uid: [u8; 32]) -> [u8; 32] {
    let mut first = [0u8; 64];
    first[12..32].copy_from_slice(&attester);
    first[56..64].copy_from_slice(&EAS_OFFCHAIN_REVOCATIONS_SLOT.to_be_bytes());
    let inner = keccak256(&first);
    let mut second = [0u8; 64];
    second[..32].copy_from_slice(&uid);
    second[32..].copy_from_slice(&inner);
    keccak256(&second)
}

fn u256_word(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(&address);
    word
}

/// Small, fully authenticated in-memory fixture for sibling unit tests.
///
/// Its state trie contains only the EAS account, whose storage trie is empty.
/// The same single state leaf therefore proves both the EAS account's presence
/// and each deterministic EOA signer's absence; an empty storage witness proves
/// each revocation slot absent. One attestation has no expiry and the other is
/// exactly on the anchored minimum-validity boundary.
#[cfg(test)]
pub(crate) struct SyntheticSnapshotFixture {
    pub raw: Vec<u8>,
    pub anchor: SnapshotAnchor,
    pub checkpoint_timestamp: u64,
    pub trusted_attesters: BTreeSet<[u8; 20]>,
}

#[cfg(test)]
pub(crate) fn synthetic_snapshot_fixture(descriptor_hash: [u8; 32]) -> SyntheticSnapshotFixture {
    use k256::ecdsa::SigningKey;

    let storage_root = keccak256(&[0x80]);
    let state_key = fixture_key_nibbles(keccak256(&EAS_CONTRACT));
    let account = fixture_rlp_list(&[
        fixture_rlp_bytes(&[1]),
        fixture_rlp_bytes(&[]),
        fixture_rlp_bytes(&storage_root),
        fixture_rlp_bytes(&EAS_RUNTIME_CODE_HASH),
    ]);
    let state_leaf = fixture_trie_leaf(&state_key, &account);
    let state_root = keccak256(&state_leaf);

    let block_number = 20_000_000u64;
    let checkpoint_timestamp = 1_800_000_000u64;
    let evaluation_timestamp = checkpoint_timestamp + 60;
    let max_checkpoint_age_seconds = 120;
    let min_remaining_validity_seconds = 3600;
    let exact_minimum_expiry = evaluation_timestamp + min_remaining_validity_seconds;
    let block_header = fixture_block_header(state_root, block_number, checkpoint_timestamp);
    let block_hash = keccak256(&block_header);

    let signing_keys = [
        SigningKey::from_bytes((&[1u8; 32]).into()).expect("valid fixture key"),
        SigningKey::from_bytes((&[2u8; 32]).into()).expect("valid fixture key"),
    ];
    let expirations = [0, exact_minimum_expiry];
    let mut trusted_attesters = BTreeSet::new();
    let mut signer_accounts = Vec::new();
    let mut attestations = Vec::new();

    for (index, key) in signing_keys.iter().enumerate() {
        let public = key.verifying_key().to_sec1_point(false);
        let public_hash = keccak256(&public.as_bytes()[1..]);
        let mut attester = [0; 20];
        attester.copy_from_slice(&public_hash[12..]);
        trusted_attesters.insert(attester);
        signer_accounts.push(serde_json::json!({
            "address": fixture_hex(&attester),
            "account_proof": [fixture_hex(&state_leaf)],
        }));

        let salt = [0x40 + index as u8; 32];
        let time = checkpoint_timestamp - 10 + index as u64;
        let expiration_time = expirations[index];
        let message = EasV2Message {
            schema: ERC8176_SCHEMA_UID,
            recipient: [0; 20],
            time,
            expiration_time,
            revocable: true,
            ref_uid: [0; 32],
            data: descriptor_hash,
            salt,
        };
        let uid = eas_v2_uid(&message);
        let digest = eas_v2_typed_data_digest(&message);
        let (signature, recovery_id) = key.sign_prehash_recoverable(&digest);
        let signature_bytes = signature.to_bytes();
        attestations.push(serde_json::json!({
            "uid": fixture_hex(&uid),
            "version": EAS_OFFCHAIN_VERSION,
            "schema": fixture_hex(&ERC8176_SCHEMA_UID),
            "recipient": fixture_hex(&[0u8; 20]),
            "time": time,
            "expiration_time": expiration_time,
            "revocable": true,
            "ref_uid": fixture_hex(&[0u8; 32]),
            "data": fixture_hex(&descriptor_hash),
            "salt": fixture_hex(&salt),
            "attester": fixture_hex(&attester),
            "signature": {
                "r": fixture_hex(&signature_bytes[..32]),
                "s": fixture_hex(&signature_bytes[32..]),
                "v": recovery_id.to_byte() + 27,
            },
            "revocation_proof": [],
        }));
    }

    let value = serde_json::json!({
        "format": SNAPSHOT_FORMAT_V1,
        "draft_commit": ERC8176_DRAFT_COMMIT,
        "chain_id": EAS_CHAIN_ID,
        "eas_contract": fixture_hex(&EAS_CONTRACT),
        "eas_runtime_code_hash": fixture_hex(&EAS_RUNTIME_CODE_HASH),
        "block_header_rlp": fixture_hex(&block_header),
        "eas_account_proof": [fixture_hex(&state_leaf)],
        "signer_accounts": signer_accounts,
        "attestations": attestations,
    });
    let raw = serde_json::to_vec(&value).expect("serialize fixture snapshot");
    let anchor = SnapshotAnchor {
        snapshot_sha256: sha256(&raw),
        checkpoint_block_hash: block_hash,
        checkpoint_block_number: block_number,
        evaluation_timestamp,
        max_checkpoint_age_seconds,
        min_remaining_validity_seconds,
    };
    SyntheticSnapshotFixture {
        raw,
        anchor,
        checkpoint_timestamp,
        trusted_attesters,
    }
}

#[cfg(test)]
fn fixture_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
fn fixture_key_nibbles(key: [u8; 32]) -> [u8; 64] {
    let mut out = [0; 64];
    for (index, byte) in key.iter().enumerate() {
        out[index * 2] = byte >> 4;
        out[index * 2 + 1] = byte & 0x0f;
    }
    out
}

#[cfg(test)]
fn fixture_compact_path(path: &[u8]) -> Vec<u8> {
    let odd = path.len() % 2 == 1;
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let mut index = 0;
    if odd {
        out.push(0x30 | path[0]);
        index = 1;
    } else {
        out.push(0x20);
    }
    while index < path.len() {
        out.push((path[index] << 4) | path[index + 1]);
        index += 2;
    }
    out
}

#[cfg(test)]
fn fixture_trie_leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
    fixture_rlp_list(&[
        fixture_rlp_bytes(&fixture_compact_path(path)),
        fixture_rlp_bytes(value),
    ])
}

#[cfg(test)]
fn fixture_rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        return bytes.to_vec();
    }
    let mut out = Vec::new();
    if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
    } else {
        let length = fixture_length_bytes(bytes.len());
        out.push(0xb7 + length.len() as u8);
        out.extend_from_slice(&length);
    }
    out.extend_from_slice(bytes);
    out
}

#[cfg(test)]
fn fixture_rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flatten().copied().collect();
    let mut out = Vec::new();
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let length = fixture_length_bytes(payload.len());
        out.push(0xf7 + length.len() as u8);
        out.extend_from_slice(&length);
    }
    out.extend_from_slice(&payload);
    out
}

#[cfg(test)]
fn fixture_length_bytes(length: usize) -> Vec<u8> {
    let bytes = length.to_be_bytes();
    bytes[bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1)..]
        .to_vec()
}

#[cfg(test)]
fn fixture_scalar(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    bytes[bytes.iter().position(|byte| *byte != 0).unwrap()..].to_vec()
}

#[cfg(test)]
fn fixture_block_header(state_root: [u8; 32], number: u64, timestamp: u64) -> Vec<u8> {
    let raw_fields = vec![
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 20],
        state_root.to_vec(),
        vec![0x04; 32],
        vec![0x05; 32],
        vec![0; 256],
        vec![],
        fixture_scalar(number),
        fixture_scalar(30_000_000),
        fixture_scalar(1),
        fixture_scalar(timestamp),
        vec![],
        vec![0x06; 32],
        vec![0; 8],
        fixture_scalar(1),
        vec![0x07; 32],
        vec![],
        vec![],
        vec![0x08; 32],
        vec![0x09; 32],
    ];
    let encoded_fields: Vec<Vec<u8>> = raw_fields
        .iter()
        .map(|field| fixture_rlp_bytes(field))
        .collect();
    fixture_rlp_list(&encoded_fields)
}

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

fn reject_duplicate_json_keys(raw: &[u8]) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    RejectDuplicateJsonKeys::deserialize(&mut deserializer)
        .map_err(|error| format!("ERC-8176 JSON syntax preflight: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("ERC-8176 JSON trailing data: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use serde_json::Value;

    #[derive(Clone, Copy, Debug)]
    enum SnapshotMutation {
        WrongSchema,
        WrongData,
        WrongUid,
        WrongSignature,
        UntrustedAttester,
        DuplicateDescriptorAttester,
        TamperedRevocationProof,
        StaleCheckpoint,
        FutureCheckpoint,
        ExpiredAttestation,
        TamperedBlockHeader,
        TamperedEasAccountProof,
        TamperedSignerAccountProof,
        SwappedSignerWitness,
        WrongEasCodeHash,
        WrongDomainName,
        WrongDomainVersion,
        WrongOffchainVersion,
        WrongDraft,
    }

    fn mutated_snapshot_error(
        fixture: &SyntheticSnapshotFixture,
        mutation: SnapshotMutation,
    ) -> String {
        let mut value: Value =
            serde_json::from_slice(&fixture.raw).expect("fixture snapshot is JSON");
        let mut anchor = fixture.anchor.clone();
        let mut trusted = fixture.trusted_attesters.clone();

        match mutation {
            SnapshotMutation::WrongSchema => {
                value["attestations"][0]["schema"] = Value::String(fixture_hex(&[0x10; 32]));
            }
            SnapshotMutation::WrongData => {
                value["attestations"][0]["data"] = Value::String(fixture_hex(&[0x11; 32]));
            }
            SnapshotMutation::WrongUid => {
                value["attestations"][0]["uid"] = Value::String(fixture_hex(&[0x12; 32]));
            }
            SnapshotMutation::WrongSignature => {
                flip_last_hex_byte(&mut value["attestations"][0]["signature"]["r"]);
            }
            SnapshotMutation::UntrustedAttester => {
                let attester = decode_hex_exact::<20>(
                    "fixture attester",
                    value["attestations"][0]["attester"]
                        .as_str()
                        .expect("attester string"),
                )
                .expect("fixture attester decodes");
                assert!(trusted.remove(&attester));
            }
            SnapshotMutation::DuplicateDescriptorAttester => {
                let duplicate = value["attestations"][0].clone();
                value["attestations"]
                    .as_array_mut()
                    .expect("attestations array")
                    .push(duplicate);
            }
            SnapshotMutation::TamperedRevocationProof => {
                value["attestations"][0]["revocation_proof"] = serde_json::json!(["0x80"]);
            }
            SnapshotMutation::StaleCheckpoint => {
                anchor.evaluation_timestamp = fixture
                    .checkpoint_timestamp
                    .checked_add(anchor.max_checkpoint_age_seconds + 1)
                    .expect("fixture timestamp does not overflow");
            }
            SnapshotMutation::FutureCheckpoint => {
                anchor.evaluation_timestamp = fixture.checkpoint_timestamp - 1;
            }
            SnapshotMutation::ExpiredAttestation => {
                value["attestations"][0]["expiration_time"] =
                    Value::from(anchor.evaluation_timestamp);
            }
            SnapshotMutation::TamperedBlockHeader => {
                flip_last_hex_byte(&mut value["block_header_rlp"]);
            }
            SnapshotMutation::TamperedEasAccountProof => {
                flip_last_hex_byte(&mut value["eas_account_proof"][0]);
            }
            SnapshotMutation::TamperedSignerAccountProof => {
                flip_last_hex_byte(&mut value["signer_accounts"][0]["account_proof"][0]);
            }
            SnapshotMutation::SwappedSignerWitness => {
                // The base fixture proves both signers absent with the same trie
                // leaf, so byte-for-byte swapping would correctly remain valid.
                // Move the sole witness to the other address instead: the first
                // signer is then deliberately paired with an incomplete proof.
                let accounts = value["signer_accounts"]
                    .as_array_mut()
                    .expect("signer account array");
                let moved = accounts[0]["account_proof"].clone();
                accounts[0]["account_proof"] = serde_json::json!([]);
                accounts[1]["account_proof"] = moved;
            }
            SnapshotMutation::WrongEasCodeHash => {
                value["eas_runtime_code_hash"] = Value::String(fixture_hex(&[0x13; 32]));
            }
            SnapshotMutation::WrongDomainName | SnapshotMutation::WrongDomainVersion => {
                let record = &mut value["attestations"][0];
                let message = message_from_json(record);
                let (name, version) = match mutation {
                    SnapshotMutation::WrongDomainName => ("EAS", EAS_DOMAIN_VERSION),
                    SnapshotMutation::WrongDomainVersion => (EAS_DOMAIN_NAME, "0.27"),
                    _ => unreachable!(),
                };
                let digest = typed_data_digest_for_domain(&message, name, version);
                sign_json_record(record, &fixture_signing_key(1), digest);
            }
            SnapshotMutation::WrongOffchainVersion => {
                value["attestations"][0]["version"] = Value::from(1);
            }
            SnapshotMutation::WrongDraft => {
                value["draft_commit"] = Value::String("deadbeef".to_string());
            }
        }

        let raw = serde_json::to_vec(&value).expect("serialize mutated fixture");
        anchor.snapshot_sha256 = sha256(&raw);
        verify_snapshot_bytes(&raw, &anchor, &trusted)
            .expect_err("mutated security input must fail closed")
    }

    fn flip_last_hex_byte(value: &mut Value) {
        let mut bytes = hex::decode(
            value
                .as_str()
                .expect("hex JSON string")
                .strip_prefix("0x")
                .expect("canonical fixture prefix"),
        )
        .expect("canonical fixture hex");
        *bytes.last_mut().expect("non-empty fixture hex") ^= 1;
        *value = Value::String(fixture_hex(&bytes));
    }

    fn message_from_json(record: &Value) -> EasV2Message {
        EasV2Message {
            schema: decode_hex_exact("fixture schema", record["schema"].as_str().unwrap()).unwrap(),
            recipient: decode_hex_exact("fixture recipient", record["recipient"].as_str().unwrap())
                .unwrap(),
            time: record["time"].as_u64().unwrap(),
            expiration_time: record["expiration_time"].as_u64().unwrap(),
            revocable: record["revocable"].as_bool().unwrap(),
            ref_uid: decode_hex_exact("fixture ref uid", record["ref_uid"].as_str().unwrap())
                .unwrap(),
            data: decode_hex_exact("fixture data", record["data"].as_str().unwrap()).unwrap(),
            salt: decode_hex_exact("fixture salt", record["salt"].as_str().unwrap()).unwrap(),
        }
    }

    fn fixture_signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes((&[byte; 32]).into()).expect("valid fixture key")
    }

    fn sign_json_record(record: &mut Value, key: &SigningKey, digest: [u8; 32]) {
        let (signature, recovery_id) = key.sign_prehash_recoverable(&digest);
        let bytes = signature.to_bytes();
        record["signature"] = serde_json::json!({
            "r": fixture_hex(&bytes[..32]),
            "s": fixture_hex(&bytes[32..]),
            "v": recovery_id.to_byte() + 27,
        });
    }

    fn typed_data_digest_for_domain(
        fields: &EasV2Message,
        domain_name: &str,
        domain_version: &str,
    ) -> [u8; 32] {
        let mut domain = Vec::with_capacity(32 * 5);
        domain.extend_from_slice(&keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ));
        domain.extend_from_slice(&keccak256(domain_name.as_bytes()));
        domain.extend_from_slice(&keccak256(domain_version.as_bytes()));
        domain.extend_from_slice(&u256_word(EAS_CHAIN_ID));
        domain.extend_from_slice(&address_word(EAS_CONTRACT));
        let domain_separator = keccak256(&domain);

        let mut message = Vec::with_capacity(32 * 10);
        message.extend_from_slice(&keccak256(
            b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)",
        ));
        message.extend_from_slice(&u256_word(u64::from(EAS_OFFCHAIN_VERSION)));
        message.extend_from_slice(&fields.schema);
        message.extend_from_slice(&address_word(fields.recipient));
        message.extend_from_slice(&u256_word(fields.time));
        message.extend_from_slice(&u256_word(fields.expiration_time));
        message.extend_from_slice(&u256_word(u64::from(fields.revocable)));
        message.extend_from_slice(&fields.ref_uid);
        message.extend_from_slice(&keccak256(&fields.data));
        message.extend_from_slice(&fields.salt);
        let struct_hash = keccak256(&message);

        let mut encoded = [0u8; 66];
        encoded[..2].copy_from_slice(&[0x19, 0x01]);
        encoded[2..34].copy_from_slice(&domain_separator);
        encoded[34..].copy_from_slice(&struct_hash);
        keccak256(&encoded)
    }

    #[test]
    fn rejects_recursive_duplicate_json_keys() {
        let error = reject_duplicate_json_keys(br#"{"a":{"uid":"x","uid":"y"}}"#)
            .expect_err("recursive duplicate must fail");
        assert!(error.contains("duplicate JSON object key `uid`"), "{error}");
    }

    #[test]
    fn hex_decoder_is_canonical_and_bounded() {
        assert_eq!(decode_hex_exact::<2>("x", "0x00ff").unwrap(), [0, 0xff]);
        assert!(decode_hex_exact::<2>("x", "0x00FF").is_err());
        assert!(decode_hex_exact::<2>("x", "00ff").is_err());
        assert!(decode_hex_exact::<2>("x", "0x00").is_err());
    }

    #[test]
    fn revocation_slot_is_nested_mapping_slot_three() {
        let address = [0x11; 20];
        let uid = [0x22; 32];
        let mut first = [0u8; 64];
        first[12..32].copy_from_slice(&address);
        first[63] = 3;
        let inner = keccak256(&first);
        let mut second = [0u8; 64];
        second[..32].copy_from_slice(&uid);
        second[32..].copy_from_slice(&inner);
        assert_eq!(
            eas_offchain_revocation_slot(address, uid),
            keccak256(&second)
        );
    }

    #[test]
    fn uid_changes_when_any_bound_field_changes() {
        let base_message = EasV2Message {
            schema: ERC8176_SCHEMA_UID,
            recipient: [0; 20],
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocable: true,
            ref_uid: [0; 32],
            data: [0x44; 32],
            salt: [0x55; 32],
        };
        let base = eas_v2_uid(&base_message);
        let changed = eas_v2_uid(&EasV2Message {
            time: base_message.time + 1,
            ..base_message
        });
        assert_ne!(base, changed);
    }

    #[test]
    fn eas_sdk_v2_uid_and_typed_data_golden() {
        // Independently generated with ethers v6.15.0 using the exact
        // OFFCHAIN_ATTESTATION_TYPES[v2] fields and getOffchainUID packed
        // types from the upstream EAS SDK.
        let message = EasV2Message {
            schema: ERC8176_SCHEMA_UID,
            recipient: [0; 20],
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocable: true,
            ref_uid: [0; 32],
            data: [0x44; 32],
            salt: [0x55; 32],
        };
        assert_eq!(
            hex::encode(eas_v2_uid(&message)),
            "9d82c255c16a87c7e08a52ccebc02069f421ff533a4757040fc149d64c06e558"
        );
        assert_eq!(
            hex::encode(eas_v2_typed_data_digest(&message)),
            "4e65e53a204630a852e53c8c9740f6c932c1f1c105b1cfc03b5ef55f1e23ba4b"
        );
    }

    #[test]
    fn rlp_rejects_noncanonical_encodings() {
        assert!(parse_rlp_item(&[0x81, 0x01]).is_err());
        assert!(parse_rlp_item(&[0xb8, 0x01, 0x00]).is_err());
        assert!(parse_rlp_item(&[0xf8, 0x01, 0x80]).is_err());
        assert!(parse_rlp_item(&[0xb9, 0x00, 0x38]).is_err());
    }

    #[test]
    fn legacy_public_recovery_vectors_remain_compatible() {
        // k256 0.13.4 public recovery vectors (src/ecdsa.rs). Expected addresses
        // were derived independently from their published compressed points.
        // This pins old-format compatibility across the 0.14 dependency update.
        let digest = sha256(b"example message");
        let vectors = [
            (
                "ce53abb3721bafc561408ce8ff99c909f7f0b18a2f788649d6470162ab1aa032",
                "3971edc523a6d6453f3fb6128d318d9db1a5ff3386feb1047d9816e780039d52",
                27,
                "691a8d05678fc962ff0f2174134379c0051cb686",
            ),
            (
                "46c05b6368a44b8810d79859441d819b8e7cdc8bfd371e35c53196f4bcacdb51",
                "35c7facce2a97b95eacba8a586d87b7958aaf8368ab29cee481f76e871dbd9cb",
                28,
                "ede35562d3555e61120a151b3c8e8e91d83a378a",
            ),
        ];
        for (r_hex, s_hex, v, address_hex) in vectors {
            let r: [u8; 32] = hex::decode(r_hex).unwrap().try_into().unwrap();
            let s: [u8; 32] = hex::decode(s_hex).unwrap().try_into().unwrap();
            let expected: [u8; 20] = hex::decode(address_hex).unwrap().try_into().unwrap();
            assert_eq!(recover_eoa(digest, r, s, v).unwrap(), expected);
            let mut changed = digest;
            changed[0] ^= 1;
            assert_ne!(recover_eoa(changed, r, s, v).ok(), Some(expected));
        }
    }

    #[test]
    fn high_s_and_noncanonical_v_are_rejected_before_recovery() {
        // secp256k1 order - 1 is necessarily high-s.
        let high_s =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
                .unwrap();
        let mut s = [0; 32];
        s.copy_from_slice(&high_s);
        assert!(recover_eoa([0; 32], u256_word(1), s, 27)
            .unwrap_err()
            .contains("high-s"));
        assert!(recover_eoa([0; 32], u256_word(1), u256_word(1), 0)
            .unwrap_err()
            .contains("27 or 28"));
    }

    #[test]
    fn no_expiry_and_exact_minimum_validity_are_accepted() {
        assert!(validate_expiration("row", 0, 1_000, 1_100).is_ok());
        assert!(validate_expiration("row", 1_100, 1_000, 1_100).is_ok());
        assert!(validate_expiration("row", 1_099, 1_000, 1_100).is_err());
        assert!(validate_expiration("row", 1_000, 1_000, 1_000).is_err());
    }

    #[test]
    fn synthetic_snapshot_verifies_end_to_end_with_empty_revocation_trie() {
        let descriptor_hash = [0x77; 32];
        let fixture = synthetic_snapshot_fixture(descriptor_hash);
        let verified =
            verify_snapshot_bytes(&fixture.raw, &fixture.anchor, &fixture.trusted_attesters)
                .expect("fully authenticated synthetic snapshot must verify");
        assert_eq!(verified.attester_count(descriptor_hash), 2);
        assert_eq!(verified.attestation_count(), 2);
        assert_eq!(verified.descriptor_count(), 1);
        assert_eq!(verified.trusted_attesters(), &fixture.trusted_attesters);
        assert_eq!(verified.snapshot_sha256(), fixture.anchor.snapshot_sha256);
        assert_eq!(
            verified.checkpoint_block_hash(),
            fixture.anchor.checkpoint_block_hash
        );
        assert_eq!(
            verified.checkpoint_block_number(),
            fixture.anchor.checkpoint_block_number
        );
        assert_eq!(
            verified.checkpoint_timestamp(),
            fixture.checkpoint_timestamp
        );
        assert_eq!(
            verified.min_remaining_validity_seconds(),
            fixture.anchor.min_remaining_validity_seconds
        );
    }

    #[test]
    fn synthetic_snapshot_security_mutations_fail_closed() {
        let fixture = synthetic_snapshot_fixture([0x77; 32]);
        let value: Value = serde_json::from_slice(&fixture.raw).unwrap();
        let message = message_from_json(&value["attestations"][0]);
        assert_eq!(
            typed_data_digest_for_domain(&message, EAS_DOMAIN_NAME, EAS_DOMAIN_VERSION),
            eas_v2_typed_data_digest(&message),
            "the test mutation helper must reproduce the canonical domain first"
        );

        let cases = [
            (SnapshotMutation::WrongSchema, "pinned ERC-8176 schema"),
            (SnapshotMutation::WrongData, ".uid mismatch"),
            (SnapshotMutation::WrongUid, ".uid mismatch"),
            (SnapshotMutation::WrongSignature, "attester mismatch"),
            (
                SnapshotMutation::UntrustedAttester,
                "not in the independently supplied trust set",
            ),
            (
                SnapshotMutation::DuplicateDescriptorAttester,
                "uid duplicates an earlier attestation",
            ),
            (
                SnapshotMutation::TamperedRevocationProof,
                "revocation proof",
            ),
            (SnapshotMutation::StaleCheckpoint, "freshness cap"),
            (SnapshotMutation::FutureCheckpoint, "after evaluation"),
            (SnapshotMutation::ExpiredAttestation, ".expiration_time"),
            (
                SnapshotMutation::TamperedBlockHeader,
                "checkpoint block hash mismatch",
            ),
            (
                SnapshotMutation::TamperedEasAccountProof,
                "verify EAS account proof",
            ),
            (
                SnapshotMutation::TamperedSignerAccountProof,
                "signer account proof",
            ),
            (
                SnapshotMutation::SwappedSignerWitness,
                "signer account proof",
            ),
            (
                SnapshotMutation::WrongEasCodeHash,
                "eas_runtime_code_hash mismatch",
            ),
            (SnapshotMutation::WrongDomainName, "attester mismatch"),
            (SnapshotMutation::WrongDomainVersion, "attester mismatch"),
            (SnapshotMutation::WrongOffchainVersion, ".version must be 2"),
            (SnapshotMutation::WrongDraft, "draft commit mismatch"),
        ];

        for (mutation, expected) in cases {
            let error = mutated_snapshot_error(&fixture, mutation);
            assert!(
                error.contains(expected),
                "{mutation:?} rejected for an unexpected reason: {error}"
            );
        }
    }

    #[test]
    fn authenticated_nonzero_revocation_state_is_rejected() {
        let fixture = synthetic_snapshot_fixture([0x77; 32]);
        let mut value: Value = serde_json::from_slice(&fixture.raw).unwrap();
        let attester = decode_hex_exact::<20>(
            "fixture attester",
            value["attestations"][0]["attester"].as_str().unwrap(),
        )
        .unwrap();
        let uid = decode_hex_exact::<32>(
            "fixture uid",
            value["attestations"][0]["uid"].as_str().unwrap(),
        )
        .unwrap();

        let revocation_slot = eas_offchain_revocation_slot(attester, uid);
        let storage_key = fixture_key_nibbles(keccak256(&revocation_slot));
        let storage_leaf = fixture_trie_leaf(&storage_key, &[1]);
        let storage_root = keccak256(&storage_leaf);

        let state_key = fixture_key_nibbles(keccak256(&EAS_CONTRACT));
        let account = fixture_rlp_list(&[
            fixture_rlp_bytes(&[1]),
            fixture_rlp_bytes(&[]),
            fixture_rlp_bytes(&storage_root),
            fixture_rlp_bytes(&EAS_RUNTIME_CODE_HASH),
        ]);
        let state_leaf = fixture_trie_leaf(&state_key, &account);
        let state_root = keccak256(&state_leaf);
        let header = fixture_block_header(
            state_root,
            fixture.anchor.checkpoint_block_number,
            fixture.checkpoint_timestamp,
        );

        value["block_header_rlp"] = Value::String(fixture_hex(&header));
        value["eas_account_proof"] = serde_json::json!([fixture_hex(&state_leaf)]);
        for witness in value["signer_accounts"].as_array_mut().unwrap() {
            witness["account_proof"] = serde_json::json!([fixture_hex(&state_leaf)]);
        }
        for record in value["attestations"].as_array_mut().unwrap() {
            record["revocation_proof"] = serde_json::json!([fixture_hex(&storage_leaf)]);
        }

        let raw = serde_json::to_vec(&value).unwrap();
        let mut anchor = fixture.anchor.clone();
        anchor.snapshot_sha256 = sha256(&raw);
        anchor.checkpoint_block_hash = keccak256(&header);
        let error = verify_snapshot_bytes(&raw, &anchor, &fixture.trusted_attesters)
            .expect_err("authenticated nonzero revocation state must fail closed");
        assert!(error.contains("is revoked at checkpoint"), "{error}");
    }

    #[test]
    fn attestation_and_witness_record_order_does_not_change_verified_set() {
        let descriptor_hash = [0x77; 32];
        let fixture = synthetic_snapshot_fixture(descriptor_hash);
        let baseline =
            verify_snapshot_bytes(&fixture.raw, &fixture.anchor, &fixture.trusted_attesters)
                .expect("baseline verifies");

        let mut value: Value = serde_json::from_slice(&fixture.raw).unwrap();
        value["attestations"].as_array_mut().unwrap().reverse();
        value["signer_accounts"].as_array_mut().unwrap().reverse();
        let reordered_raw = serde_json::to_vec(&value).unwrap();
        let mut reordered_anchor = fixture.anchor.clone();
        reordered_anchor.snapshot_sha256 = sha256(&reordered_raw);
        let reordered = verify_snapshot_bytes(
            &reordered_raw,
            &reordered_anchor,
            &fixture.trusted_attesters,
        )
        .expect("record order is not authority");

        assert_eq!(baseline.by_descriptor, reordered.by_descriptor);
        assert_eq!(baseline.attestation_count(), reordered.attestation_count());
        assert_eq!(baseline.descriptor_count(), reordered.descriptor_count());
        assert_eq!(
            baseline.attesters(descriptor_hash),
            reordered.attesters(descriptor_hash)
        );
    }
}
