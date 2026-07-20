//! Deterministic, hash-bound full-file curation overlay for the ERC-7730
//! registry.
//!
//! The upstream checkout remains an unmodified baseline. Every approved local
//! change is a complete replacement file whose before/after bytes are bound by
//! the checked-in manifest. There is deliberately no patch language, merge
//! semantics, wildcard, or path fallback here.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_VERSION: u64 = 2;
const OVERLAY_MODE: &str = "full-file-replacement";
const UPSTREAM_REPOSITORY: &str = "https://github.com/ethereum/clear-signing-erc7730-registry.git";
const VENDOR_CORPUS_DOMAIN: &str = "pqsigner/erc7730-vendor-corpus-v1";
const EXCLUDED_FIXTURE_CORPUS_DOMAIN: &str = "pqsigner/erc7730-excluded-fixture-corpus-v1";
const TOOL_INPUT_TREE_DOMAIN: &str = "pqsigner/erc7730-tool-input-tree-v1";
const UPSTREAM_SCHEMA_PATH: &str = "specs/erc7730-v2.schema.json";
const POLICY_PATH: &str = "secure/data/erc7730/policy.toml";
const REPLACEMENT_DIRECTORY: &str = "files";
const VENDORED_MARKER_PATH: &str = ".pqsigner-erc7730-vendor";
const VENDORED_README_PATH: &str = "README.md";

// These scalar identities bind dependency resolution, workspace configuration,
// crate boundaries, and the selected toolchain. The recursively receipted
// crate trees below bind the complete in-repository compilation closure used
// by the host curation/compiler path, including future modules, build scripts,
// custom target paths, and data files.
// This is still a source receipt, not signed-release or build-environment
// authority; those remain later gates.
const TOOL_INPUT_PATHS: &[&str] = &[
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    "dbgen/Cargo.toml",
    "pqsigner-erc7730/Cargo.toml",
    "pqsigner-fi/Cargo.toml",
    "proto/Cargo.toml",
    "rust-toolchain.toml",
    "shared/Cargo.toml",
    "tx-core/Cargo.toml",
    "tx/Cargo.toml",
    "xtask/Cargo.toml",
];
const TOOL_INPUT_TREE_PATHS: &[&str] = &[
    ".cargo",
    "dbgen",
    "pqsigner-erc7730",
    "pqsigner-fi",
    "proto",
    "shared",
    "tx-core",
    "tx",
    "xtask",
];
const CAPABILITY_INPUT_PATHS: &[&str] = &["secure/data/erc20.json"];
// Cargo and rustup retain extensionless compatibility names and prefer them
// when both forms exist. Their absence is therefore part of the receipt: an
// unbound shadow file must fail before the declared `.toml` identity can be
// mistaken for the effective configuration/toolchain selection.
const FORBIDDEN_SHADOW_INPUT_PATHS: &[&str] = &[".cargo/config", "rust-toolchain"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CorpusReceipt {
    pub(crate) file_count: usize,
    pub(crate) byte_count: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryCheckoutIdentity {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) tree: String,
    pub(crate) schema_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplacementIdentity {
    pub(crate) path: String,
    pub(crate) upstream_sha256: [u8; 32],
    pub(crate) replacement_sha256: [u8; 32],
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    mode: String,
    upstream: UpstreamIdentity,
    curated_corpus: CorpusIdentity,
    policy: FileIdentity,
    tool_inputs: Vec<FileIdentity>,
    tool_input_trees: Vec<TreeIdentity>,
    capability_inputs: Vec<FileIdentity>,
    replacements: Vec<Replacement>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamIdentity {
    repository: String,
    commit: String,
    tree: String,
    schema: FileIdentity,
    corpus: CorpusIdentity,
    excluded_fixtures: CorpusIdentity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusIdentity {
    domain: String,
    files: u64,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeIdentity {
    path: String,
    domain: String,
    files: u64,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    path: String,
    upstream_bytes: u64,
    upstream_sha256: String,
    replacement_bytes: u64,
    replacement_sha256: String,
}

/// A syntactically strict manifest whose local policy/tool/replacement inputs
/// have all been verified. Upstream Git and corpus identity are checked
/// separately because `gen-erc7730-descriptors --check` intentionally works
/// from a clean repository without an adjacent upstream clone.
pub(crate) struct VerifiedOverlay {
    manifest: Manifest,
    manifest_sha256: [u8; 32],
    replacement_root: PathBuf,
}

impl VerifiedOverlay {
    pub(crate) fn load_and_verify_local_inputs(
        workspace_root: &Path,
        manifest_path: &Path,
    ) -> Result<Self, String> {
        require_regular_file(manifest_path, "curation manifest")?;
        let bytes = fs::read(manifest_path).map_err(|error| {
            format!(
                "read curation manifest {}: {error}",
                manifest_path.display()
            )
        })?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse strict curation manifest {}: {error}",
                manifest_path.display()
            )
        })?;
        validate_manifest_shape(&manifest)?;
        verify_shadow_inputs_absent(workspace_root)?;

        verify_file_identity(workspace_root, &manifest.policy, "curation policy")?;
        for identity in &manifest.tool_inputs {
            verify_file_identity(workspace_root, identity, "curation tool input")?;
        }
        for identity in &manifest.tool_input_trees {
            verify_tree_identity(workspace_root, identity, "curation tool input tree")?;
        }
        for identity in &manifest.capability_inputs {
            verify_file_identity(workspace_root, identity, "curation capability input")?;
        }

        let manifest_parent = manifest_path.parent().ok_or_else(|| {
            format!(
                "curation manifest has no parent: {}",
                manifest_path.display()
            )
        })?;
        let replacement_root = manifest_parent.join(REPLACEMENT_DIRECTORY);
        verify_replacement_inventory(&replacement_root, &manifest.replacements)?;
        for replacement in &manifest.replacements {
            let path = replacement_root.join(&replacement.path);
            verify_file_bytes(
                &path,
                replacement.replacement_bytes,
                &replacement.replacement_sha256,
                "curation replacement",
            )?;
        }

        Ok(Self {
            manifest,
            manifest_sha256: Sha256::digest(&bytes).into(),
            replacement_root,
        })
    }

    pub(crate) fn replacement_count(&self) -> usize {
        self.manifest.replacements.len()
    }

    pub(crate) fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    pub(crate) fn upstream_commit(&self) -> &str {
        &self.manifest.upstream.commit
    }

    pub(crate) fn upstream_tree(&self) -> &str {
        &self.manifest.upstream.tree
    }

    pub(crate) fn policy_sha256(&self) -> Result<[u8; 32], String> {
        parse_sha256(&self.manifest.policy.sha256)
    }

    pub(crate) fn replacement_identities(&self) -> Result<Vec<ReplacementIdentity>, String> {
        self.manifest
            .replacements
            .iter()
            .map(|replacement| {
                Ok(ReplacementIdentity {
                    path: replacement.path.clone(),
                    upstream_sha256: parse_sha256(&replacement.upstream_sha256)?,
                    replacement_sha256: parse_sha256(&replacement.replacement_sha256)?,
                })
            })
            .collect()
    }

    pub(crate) fn verify_selected_policy(
        &self,
        workspace_root: &Path,
        selected_policy: &Path,
    ) -> Result<(), String> {
        let bound =
            fs::canonicalize(workspace_root.join(&self.manifest.policy.path)).map_err(|error| {
                format!(
                    "canonicalize manifest-bound policy {}: {error}",
                    self.manifest.policy.path
                )
            })?;
        let selected = fs::canonicalize(selected_policy).map_err(|error| {
            format!(
                "canonicalize selected curation policy {}: {error}",
                selected_policy.display()
            )
        })?;
        if selected != bound {
            return Err(format!(
                "selected policy is not the manifest-bound policy: selected={} bound={}",
                selected.display(),
                bound.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_upstream_checkout(&self, root: &Path) -> Result<(), String> {
        let identity = verify_official_clean_checkout(root)?;
        if identity.repository != self.manifest.upstream.repository {
            return Err(format!(
                "upstream origin mismatch: expected `{}`, got `{}`",
                self.manifest.upstream.repository, identity.repository
            ));
        }
        if identity.commit != self.manifest.upstream.commit {
            return Err(format!(
                "upstream commit mismatch: expected {}, got {}",
                self.manifest.upstream.commit, identity.commit
            ));
        }
        if identity.tree != self.manifest.upstream.tree {
            return Err(format!(
                "upstream tree mismatch: expected {}, got {}",
                self.manifest.upstream.tree, identity.tree
            ));
        }
        let expected_schema = parse_sha256(&self.manifest.upstream.schema.sha256)?;
        if identity.schema_sha256 != expected_schema {
            return Err(format!(
                "upstream ERC-7730 schema hash mismatch for {}: expected {}, got {}",
                root.join(UPSTREAM_SCHEMA_PATH).display(),
                self.manifest.upstream.schema.sha256,
                hex::encode(identity.schema_sha256),
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_source_receipts(
        &self,
        corpus: CorpusReceipt,
        excluded_fixtures: CorpusReceipt,
    ) -> Result<(), String> {
        verify_receipt(
            "upstream security corpus",
            corpus,
            &self.manifest.upstream.corpus,
        )?;
        verify_receipt(
            "upstream excluded-fixture corpus",
            excluded_fixtures,
            &self.manifest.upstream.excluded_fixtures,
        )
    }

    /// Apply only complete replacement bytes to an already verified pristine
    /// staging copy. A mismatch is fatal before the affected target is written.
    pub(crate) fn apply_to_staging(&self, staging: &Path) -> Result<(), String> {
        for replacement in &self.manifest.replacements {
            let target = staging.join(&replacement.path);
            verify_file_bytes(
                &target,
                replacement.upstream_bytes,
                &replacement.upstream_sha256,
                "staged upstream curation target",
            )?;
            let replacement_path = self.replacement_root.join(&replacement.path);
            let bytes = fs::read(&replacement_path).map_err(|error| {
                format!(
                    "read curation replacement {}: {error}",
                    replacement_path.display()
                )
            })?;
            verify_bytes(
                &replacement_path,
                &bytes,
                replacement.replacement_bytes,
                &replacement.replacement_sha256,
                "curation replacement",
            )?;
            fs::write(&target, &bytes)
                .map_err(|error| format!("write curated target {}: {error}", target.display()))?;
            verify_file_bytes(
                &target,
                replacement.replacement_bytes,
                &replacement.replacement_sha256,
                "applied curated target",
            )?;
        }
        Ok(())
    }

    pub(crate) fn verify_applied_diff(
        &self,
        source_root: &Path,
        source_files: &BTreeSet<PathBuf>,
        staged_root: &Path,
        staged_files: &BTreeSet<PathBuf>,
    ) -> Result<(), String> {
        let source_rel = relative_file_set(source_root, source_files)?;
        let staged_rel = relative_file_set(staged_root, staged_files)?;
        if source_rel != staged_rel {
            return Err("curation overlay added or removed trusted corpus paths".to_string());
        }

        let mut changed = BTreeSet::new();
        for relative in source_rel {
            let source = fs::read(source_root.join(&relative)).map_err(|error| {
                format!("read upstream diff source {}: {error}", relative.display())
            })?;
            let staged = fs::read(staged_root.join(&relative)).map_err(|error| {
                format!("read staged diff target {}: {error}", relative.display())
            })?;
            if source != staged {
                changed.insert(path_to_slash_string(&relative)?);
            }
        }
        let declared = self
            .manifest
            .replacements
            .iter()
            .map(|replacement| replacement.path.clone())
            .collect::<BTreeSet<_>>();
        if changed != declared {
            return Err(format!(
                "applied curation diff set differs from manifest: declared={declared:?} changed={changed:?}"
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_curated_receipt(&self, receipt: CorpusReceipt) -> Result<(), String> {
        verify_receipt(
            "curated security corpus",
            receipt,
            &self.manifest.curated_corpus,
        )
    }

    pub(crate) fn verify_checked_in_tree(&self, root: &Path) -> Result<CorpusReceipt, String> {
        let files = collect_curated_corpus_files(root)?;
        let receipt = corpus_receipt(root, &files, VENDOR_CORPUS_DOMAIN.as_bytes())?;
        self.verify_curated_receipt(receipt)?;
        for replacement in &self.manifest.replacements {
            let vendored = root.join(&replacement.path);
            let overlay = self.replacement_root.join(&replacement.path);
            let vendored_bytes = fs::read(&vendored).map_err(|error| {
                format!(
                    "read checked-in curated file {}: {error}",
                    vendored.display()
                )
            })?;
            let overlay_bytes = fs::read(&overlay).map_err(|error| {
                format!("read overlay replacement {}: {error}", overlay.display())
            })?;
            if vendored_bytes != overlay_bytes {
                return Err(format!(
                    "checked-in curated file differs from its full replacement: {}",
                    replacement.path
                ));
            }
        }
        Ok(receipt)
    }
}

/// Verify a registry checkout without requiring the manifest-pinned revision.
/// This is the candidate-side provenance gate for `diff-registry`: only the
/// official repository, an exact Git top level, clean security inputs, and a
/// regular v2 schema are accepted. The observed commit/tree/schema identities
/// are returned for the deterministic report.
pub(crate) fn verify_official_clean_checkout(
    root: &Path,
) -> Result<RegistryCheckoutIdentity, String> {
    let top_level = git(root, &["rev-parse", "--show-toplevel"])?;
    let canonical_top = fs::canonicalize(top_level.trim()).map_err(|error| {
        format!(
            "canonicalize upstream Git top-level `{}`: {error}",
            top_level.trim()
        )
    })?;
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize upstream root {}: {error}", root.display()))?;
    if canonical_top != canonical_root {
        return Err(format!(
            "upstream registry root is not its Git top-level: root={} top-level={}",
            canonical_root.display(),
            canonical_top.display()
        ));
    }

    let repository = git(root, &["remote", "get-url", "origin"])?
        .trim()
        .to_string();
    if repository != UPSTREAM_REPOSITORY {
        return Err(format!(
            "upstream origin mismatch: expected `{UPSTREAM_REPOSITORY}`, got `{repository}`"
        ));
    }
    let commit = git(root, &["rev-parse", "HEAD"])?.trim().to_string();
    validate_lower_hex(&commit, 20, "upstream commit")?;
    let tree = git(root, &["rev-parse", "HEAD^{tree}"])?.trim().to_string();
    validate_lower_hex(&tree, 20, "upstream tree")?;
    let status = git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "registry",
            "ercs",
            UPSTREAM_SCHEMA_PATH,
        ],
    )?;
    if !status.is_empty() {
        return Err(format!(
            "upstream security inputs are dirty; refuse mixed committed/working-tree provenance:\n{status}"
        ));
    }
    let schema = root.join(UPSTREAM_SCHEMA_PATH);
    require_regular_file(&schema, "upstream ERC-7730 schema")?;
    let schema_bytes = fs::read(&schema).map_err(|error| {
        format!(
            "read upstream ERC-7730 schema {}: {error}",
            schema.display()
        )
    })?;

    Ok(RegistryCheckoutIdentity {
        repository,
        commit,
        tree,
        schema_sha256: Sha256::digest(schema_bytes).into(),
    })
}

pub(crate) fn corpus_receipt(
    root: &Path,
    files: &BTreeSet<PathBuf>,
    domain: &[u8],
) -> Result<CorpusReceipt, String> {
    let count = u64::try_from(files.len())
        .map_err(|_| "vendor corpus file count does not fit u64".to_string())?;
    let mut aggregate = Sha256::new();
    aggregate.update(domain);
    aggregate.update(count.to_be_bytes());
    let mut byte_count = 0u64;
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("corpus source escaped root: {}", path.display()))?;
        let relative = path_to_slash_string(relative)?;
        let path_len = u32::try_from(relative.len())
            .map_err(|_| format!("corpus path is too long: {relative}"))?;
        let bytes = fs::read(path)
            .map_err(|error| format!("read corpus file {}: {error}", path.display()))?;
        let file_len = u64::try_from(bytes.len())
            .map_err(|_| format!("corpus file is too large: {}", path.display()))?;
        byte_count = byte_count
            .checked_add(file_len)
            .ok_or_else(|| "vendor corpus byte count overflow".to_string())?;
        let file_hash = Sha256::digest(&bytes);
        aggregate.update(path_len.to_be_bytes());
        aggregate.update(relative.as_bytes());
        aggregate.update(file_len.to_be_bytes());
        aggregate.update(file_hash);
    }
    Ok(CorpusReceipt {
        file_count: files.len(),
        byte_count,
        sha256: aggregate.finalize().into(),
    })
}

fn validate_manifest_shape(manifest: &Manifest) -> Result<(), String> {
    if manifest.manifest_version != MANIFEST_VERSION {
        return Err(format!(
            "unsupported curation manifest version {}; expected {MANIFEST_VERSION}",
            manifest.manifest_version
        ));
    }
    if manifest.mode != OVERLAY_MODE {
        return Err(format!(
            "unsupported curation mode `{}`; expected `{OVERLAY_MODE}`",
            manifest.mode
        ));
    }
    if manifest.upstream.repository != UPSTREAM_REPOSITORY {
        return Err(format!(
            "unexpected upstream repository `{}`; expected `{UPSTREAM_REPOSITORY}`",
            manifest.upstream.repository
        ));
    }
    validate_lower_hex(&manifest.upstream.commit, 20, "upstream commit")?;
    validate_lower_hex(&manifest.upstream.tree, 20, "upstream tree")?;
    if manifest.upstream.schema.path != UPSTREAM_SCHEMA_PATH {
        return Err(format!(
            "unexpected upstream schema path `{}`; expected `{UPSTREAM_SCHEMA_PATH}`",
            manifest.upstream.schema.path
        ));
    }
    validate_lower_hex(
        &manifest.upstream.schema.sha256,
        32,
        "upstream schema SHA-256",
    )?;
    if manifest.policy.path != POLICY_PATH {
        return Err(format!(
            "unexpected curation policy path `{}`; expected `{POLICY_PATH}`",
            manifest.policy.path
        ));
    }
    validate_lower_hex(&manifest.policy.sha256, 32, "curation policy SHA-256")?;

    validate_corpus_identity(
        &manifest.upstream.corpus,
        VENDOR_CORPUS_DOMAIN,
        "upstream corpus",
    )?;
    validate_corpus_identity(
        &manifest.curated_corpus,
        VENDOR_CORPUS_DOMAIN,
        "curated corpus",
    )?;
    validate_corpus_identity(
        &manifest.upstream.excluded_fixtures,
        EXCLUDED_FIXTURE_CORPUS_DOMAIN,
        "excluded-fixture corpus",
    )?;
    if manifest.upstream.corpus.files != manifest.curated_corpus.files {
        return Err("full-file overlay may not add or remove corpus files".to_string());
    }

    let tool_paths = manifest
        .tool_inputs
        .iter()
        .map(|identity| identity.path.as_str())
        .collect::<Vec<_>>();
    if tool_paths != TOOL_INPUT_PATHS {
        return Err(format!(
            "tool input identity set/order mismatch: expected {TOOL_INPUT_PATHS:?}, got {tool_paths:?}"
        ));
    }
    for identity in &manifest.tool_inputs {
        validate_repo_relative_path(&identity.path, false)?;
        validate_lower_hex(&identity.sha256, 32, "tool input SHA-256")?;
    }

    let tree_paths = manifest
        .tool_input_trees
        .iter()
        .map(|identity| identity.path.as_str())
        .collect::<Vec<_>>();
    if tree_paths != TOOL_INPUT_TREE_PATHS {
        return Err(format!(
            "tool input tree identity set/order mismatch: expected {TOOL_INPUT_TREE_PATHS:?}, got {tree_paths:?}"
        ));
    }
    for identity in &manifest.tool_input_trees {
        validate_repo_relative_path(&identity.path, false)?;
        if identity.domain != TOOL_INPUT_TREE_DOMAIN {
            return Err(format!(
                "tool input tree domain mismatch for {}: expected `{TOOL_INPUT_TREE_DOMAIN}`, got `{}`",
                identity.path, identity.domain
            ));
        }
        if identity.files == 0 {
            return Err(format!(
                "tool input tree must contain at least one file: {}",
                identity.path
            ));
        }
        validate_lower_hex(&identity.sha256, 32, "tool input tree SHA-256")?;
    }

    let capability_paths = manifest
        .capability_inputs
        .iter()
        .map(|identity| identity.path.as_str())
        .collect::<Vec<_>>();
    if capability_paths != CAPABILITY_INPUT_PATHS {
        return Err(format!(
            "capability input identity set/order mismatch: expected {CAPABILITY_INPUT_PATHS:?}, got {capability_paths:?}"
        ));
    }
    for identity in &manifest.capability_inputs {
        validate_repo_relative_path(&identity.path, false)?;
        validate_lower_hex(&identity.sha256, 32, "capability input SHA-256")?;
    }

    if manifest.replacements.is_empty() {
        return Err("curation manifest must declare at least one replacement".to_string());
    }
    let mut previous: Option<&str> = None;
    for replacement in &manifest.replacements {
        validate_repo_relative_path(&replacement.path, true)?;
        if previous.is_some_and(|path| path >= replacement.path.as_str()) {
            return Err(format!(
                "curation replacements must be unique and lexicographically sorted; `{}` follows `{}`",
                replacement.path,
                previous.unwrap_or("")
            ));
        }
        previous = Some(&replacement.path);
        validate_lower_hex(
            &replacement.upstream_sha256,
            32,
            "replacement upstream SHA-256",
        )?;
        validate_lower_hex(
            &replacement.replacement_sha256,
            32,
            "replacement curated SHA-256",
        )?;
        if replacement.upstream_sha256 == replacement.replacement_sha256 {
            return Err(format!(
                "declared curation is byte-identical to upstream: {}",
                replacement.path
            ));
        }
    }
    Ok(())
}

fn validate_corpus_identity(
    identity: &CorpusIdentity,
    expected_domain: &str,
    label: &str,
) -> Result<(), String> {
    if identity.domain != expected_domain {
        return Err(format!(
            "{label} domain mismatch: expected `{expected_domain}`, got `{}`",
            identity.domain
        ));
    }
    if identity.files == 0 {
        return Err(format!("{label} must contain at least one file"));
    }
    validate_lower_hex(&identity.sha256, 32, &format!("{label} SHA-256"))
}

fn validate_repo_relative_path(path: &str, replacement: bool) -> Result<(), String> {
    if path.is_empty() || path.contains('\\') {
        return Err(format!("non-canonical relative path `{path}`"));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe or non-canonical relative path `{path}`"));
    }
    if path_to_slash_string(parsed)? != path {
        return Err(format!("non-canonical relative path `{path}`"));
    }
    if replacement {
        let mut components = parsed.components();
        let first = components.next().and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        });
        if !matches!(first, Some("registry" | "ercs")) || !path.ends_with(".json") {
            return Err(format!(
                "curation target must be a canonical registry/ or ercs/ JSON path: `{path}`"
            ));
        }
        if path.split('/').any(|component| component == "tests")
            || path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.contains(".tests."))
        {
            return Err(format!(
                "curation target may not be an excluded fixture: `{path}`"
            ));
        }
    }
    Ok(())
}

fn validate_lower_hex(value: &str, byte_len: usize, label: &str) -> Result<(), String> {
    if value.len() != byte_len.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {} lowercase hexadecimal characters",
            byte_len.saturating_mul(2)
        ));
    }
    Ok(())
}

fn identity_receipt(identity: &CorpusIdentity) -> Result<CorpusReceipt, String> {
    let file_count = usize::try_from(identity.files)
        .map_err(|_| "manifest corpus file count does not fit usize".to_string())?;
    Ok(CorpusReceipt {
        file_count,
        byte_count: identity.bytes,
        sha256: parse_sha256(&identity.sha256)?,
    })
}

fn verify_receipt(
    label: &str,
    actual: CorpusReceipt,
    expected: &CorpusIdentity,
) -> Result<(), String> {
    let expected = identity_receipt(expected)?;
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "{label} receipt mismatch: expected files={} bytes={} sha256={}, got files={} bytes={} sha256={}",
        expected.file_count,
        expected.byte_count,
        hex::encode(expected.sha256),
        actual.file_count,
        actual.byte_count,
        hex::encode(actual.sha256),
    ))
}

fn verify_file_identity(root: &Path, identity: &FileIdentity, label: &str) -> Result<(), String> {
    validate_repo_relative_path(&identity.path, false)?;
    let path = root.join(&identity.path);
    require_regular_file(&path, label)?;
    let bytes =
        fs::read(&path).map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != identity.sha256 {
        return Err(format!(
            "{label} hash mismatch for {}: expected {}, got {actual}",
            path.display(),
            identity.sha256
        ));
    }
    Ok(())
}

fn verify_shadow_inputs_absent(root: &Path) -> Result<(), String> {
    for relative in FORBIDDEN_SHADOW_INPUT_PATHS {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(format!(
                    "forbidden unreceipted legacy build-input shadow exists: {}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect forbidden legacy build-input shadow {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn verify_tree_identity(root: &Path, identity: &TreeIdentity, label: &str) -> Result<(), String> {
    let tree_root = root.join(&identity.path);
    let files = collect_regular_tree_files(&tree_root)?;
    let actual = corpus_receipt(root, &files, identity.domain.as_bytes())?;
    let expected = CorpusReceipt {
        file_count: usize::try_from(identity.files)
            .map_err(|_| format!("{label} file count does not fit usize: {}", identity.path))?,
        byte_count: identity.bytes,
        sha256: parse_sha256(&identity.sha256)?,
    };
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "{label} receipt mismatch for {}: expected files={} bytes={} sha256={}, got files={} bytes={} sha256={}",
        identity.path,
        expected.file_count,
        expected.byte_count,
        hex::encode(expected.sha256),
        actual.file_count,
        actual.byte_count,
        hex::encode(actual.sha256),
    ))
}

fn collect_regular_tree_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect tool input tree {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "tool input tree root must be a non-symlink directory: {}",
            root.display()
        ));
    }
    let mut out = BTreeSet::new();
    collect_regular_tree_files_recursive(root, &mut out)?;
    Ok(out)
}

fn collect_regular_tree_files_recursive(
    directory: &Path,
    out: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read tool input tree {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "read tool input tree entry under {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            format!("inspect tool input tree entry {}: {error}", path.display())
        })?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden in tool input tree: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            collect_regular_tree_files_recursive(&path, out)?;
        } else if file_type.is_file() {
            // Validate UTF-8/canonical spelling before accepting the path into
            // the deterministic receipt. `corpus_receipt` repeats this check
            // for the workspace-relative spelling it hashes.
            path_to_slash_string(&path)?;
            out.insert(path);
        } else {
            return Err(format!(
                "unsupported tool input tree entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_file_bytes(
    path: &Path,
    expected_len: u64,
    expected_hash: &str,
    label: &str,
) -> Result<(), String> {
    require_regular_file(path, label)?;
    let bytes =
        fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    verify_bytes(path, &bytes, expected_len, expected_hash, label)
}

fn verify_bytes(
    path: &Path,
    bytes: &[u8],
    expected_len: u64,
    expected_hash: &str,
    label: &str,
) -> Result<(), String> {
    let actual_len = u64::try_from(bytes.len())
        .map_err(|_| format!("{label} is too large: {}", path.display()))?;
    let actual_hash = hex::encode(Sha256::digest(bytes));
    if actual_len != expected_len || actual_hash != expected_hash {
        return Err(format!(
            "{label} mismatch for {}: expected bytes={} sha256={}, got bytes={} sha256={actual_hash}",
            path.display(),
            expected_len,
            expected_hash,
            actual_len,
        ));
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn verify_replacement_inventory(root: &Path, replacements: &[Replacement]) -> Result<(), String> {
    let actual = collect_replacement_files(root)?;
    let expected = replacements
        .iter()
        .map(|replacement| replacement.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "replacement-file inventory differs from manifest: expected={expected:?} actual={actual:?}"
        ));
    }
    Ok(())
}

fn collect_replacement_files(root: &Path) -> Result<BTreeSet<String>, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect replacement directory {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "replacement root must be a non-symlink directory: {}",
            root.display()
        ));
    }
    let mut out = BTreeSet::new();
    collect_replacement_files_recursive(root, root, &mut out)?;
    Ok(out)
}

fn collect_replacement_files_recursive(
    root: &Path,
    directory: &Path,
    out: &mut BTreeSet<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "read replacement directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "read replacement entry under {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect replacement entry {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden in curation replacements: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            collect_replacement_files_recursive(root, &path, out)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("replacement escaped root: {}", path.display()))?;
            let relative = path_to_slash_string(relative)?;
            validate_repo_relative_path(&relative, true)?;
            out.insert(relative);
        } else {
            return Err(format!(
                "unsupported replacement filesystem entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn collect_curated_corpus_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    validate_curated_root_inventory(root)?;
    let mut out = BTreeSet::new();
    for top in ["registry", "ercs"] {
        collect_curated_corpus_recursive(&root.join(top), false, &mut out)?;
    }
    Ok(out)
}

fn validate_curated_root_inventory(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect curated registry root {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "curated registry root must be a non-symlink directory: {}",
            root.display()
        ));
    }

    let mut saw_registry = false;
    let mut saw_ercs = false;
    for entry in fs::read_dir(root)
        .map_err(|error| format!("read curated registry root {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "read curated registry root entry under {}: {error}",
                root.display()
            )
        })?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-UTF-8 curated registry root entry: {}", path.display()))?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "inspect curated registry root entry {}: {error}",
                path.display()
            )
        })?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden at curated registry root: {}",
                path.display()
            ));
        }
        match name.as_str() {
            "registry" | "ercs" if file_type.is_dir() => {
                saw_registry |= name == "registry";
                saw_ercs |= name == "ercs";
            }
            VENDORED_MARKER_PATH | VENDORED_README_PATH if file_type.is_file() => {}
            _ => {
                return Err(format!(
                    "unexpected unreceipted curated registry root entry: {}",
                    path.display()
                ));
            }
        }
    }
    if !saw_registry || !saw_ercs {
        return Err(
            "curated registry root must contain registry/ and ercs/ directories".to_string(),
        );
    }
    Ok(())
}

fn collect_curated_corpus_recursive(
    directory: &Path,
    under_tests: bool,
    out: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        format!(
            "inspect curated corpus directory {}: {error}",
            directory.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "curated corpus directory must be a non-symlink directory: {}",
            directory.display()
        ));
    }
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "read curated corpus directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "read curated corpus entry under {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect curated corpus entry {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is forbidden in curated corpus: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            let tests = path.file_name().is_some_and(|name| name == "tests");
            collect_curated_corpus_recursive(&path, under_tests || tests, out)?;
        } else if file_type.is_file() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("non-UTF-8 curated corpus filename: {}", path.display()))?;
            if name.to_ascii_lowercase().ends_with(".json") && !name.ends_with(".json") {
                return Err(format!(
                    "non-canonical JSON filename in curated corpus: {name}"
                ));
            }
            if name.ends_with(".json") {
                if under_tests || name.contains(".tests.") {
                    return Err(format!(
                        "excluded fixture unexpectedly present in curated corpus: {}",
                        path.display()
                    ));
                }
                out.insert(path);
            }
        } else {
            return Err(format!(
                "unsupported curated corpus entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn relative_file_set(root: &Path, files: &BTreeSet<PathBuf>) -> Result<BTreeSet<PathBuf>, String> {
    files
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .map(PathBuf::from)
                .map_err(|_| format!("corpus file escaped root: {}", path.display()))
        })
        .collect()
}

fn path_to_slash_string(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?;
    if std::path::MAIN_SEPARATOR != '/' && text.contains(std::path::MAIN_SEPARATOR) {
        Ok(text.replace(std::path::MAIN_SEPARATOR, "/"))
    } else {
        Ok(text.to_string())
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], String> {
    validate_lower_hex(value, 32, "SHA-256")?;
    let bytes = hex::decode(value).map_err(|error| format!("decode SHA-256: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "decoded SHA-256 has the wrong length".to_string())
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("run git in {}: {error}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("git output was not UTF-8 in {}: {error}", root.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn one_replacement(path: &str, upstream: &[u8], curated: &[u8]) -> Replacement {
        Replacement {
            path: path.to_string(),
            upstream_bytes: upstream.len() as u64,
            upstream_sha256: hash(upstream),
            replacement_bytes: curated.len() as u64,
            replacement_sha256: hash(curated),
        }
    }

    fn test_overlay(root: &Path, replacement: Replacement) -> VerifiedOverlay {
        VerifiedOverlay {
            manifest: Manifest {
                manifest_version: MANIFEST_VERSION,
                mode: OVERLAY_MODE.to_string(),
                upstream: UpstreamIdentity {
                    repository: UPSTREAM_REPOSITORY.to_string(),
                    commit: "00".repeat(20),
                    tree: "11".repeat(20),
                    schema: FileIdentity {
                        path: UPSTREAM_SCHEMA_PATH.to_string(),
                        sha256: "22".repeat(32),
                    },
                    corpus: CorpusIdentity {
                        domain: VENDOR_CORPUS_DOMAIN.to_string(),
                        files: 1,
                        bytes: replacement.upstream_bytes,
                        sha256: "33".repeat(32),
                    },
                    excluded_fixtures: CorpusIdentity {
                        domain: EXCLUDED_FIXTURE_CORPUS_DOMAIN.to_string(),
                        files: 1,
                        bytes: 1,
                        sha256: "44".repeat(32),
                    },
                },
                curated_corpus: CorpusIdentity {
                    domain: VENDOR_CORPUS_DOMAIN.to_string(),
                    files: 1,
                    bytes: replacement.replacement_bytes,
                    sha256: "55".repeat(32),
                },
                policy: FileIdentity {
                    path: POLICY_PATH.to_string(),
                    sha256: "66".repeat(32),
                },
                tool_inputs: Vec::new(),
                tool_input_trees: Vec::new(),
                capability_inputs: Vec::new(),
                replacements: vec![replacement],
            },
            manifest_sha256: [0u8; 32],
            replacement_root: root.to_path_buf(),
        }
    }

    #[test]
    fn full_replacement_is_deterministic_and_binds_before_and_after_bytes() {
        let temp = tempfile::tempdir().expect("create curation test directory");
        let replacement_root = temp.path().join("overlay");
        let target_rel = "registry/example/calldata-example.json";
        let replacement_path = replacement_root.join(target_rel);
        let upstream = br#"{"value":"upstream"}\n"#;
        let curated = br#"{"value":"curated"}\n"#;
        fs::create_dir_all(replacement_path.parent().unwrap()).unwrap();
        fs::write(&replacement_path, curated).unwrap();
        let overlay = test_overlay(
            &replacement_root,
            one_replacement(target_rel, upstream, curated),
        );

        let mut outputs = Vec::new();
        for index in 0..2 {
            let staging = temp.path().join(format!("staging-{index}"));
            let target = staging.join(target_rel);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, upstream).unwrap();
            overlay.apply_to_staging(&staging).unwrap();
            outputs.push(fs::read(target).unwrap());
        }
        assert_eq!(outputs[0], curated);
        assert_eq!(outputs[0], outputs[1]);

        let staging = temp.path().join("tampered-staging");
        let target = staging.join(target_rel);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"tampered upstream").unwrap();
        let before = fs::read(&target).unwrap();
        let error = overlay.apply_to_staging(&staging).unwrap_err();
        assert!(error.contains("staged upstream curation target mismatch"));
        assert_eq!(fs::read(&target).unwrap(), before, "failure wrote target");

        fs::write(&target, upstream).unwrap();
        fs::write(&replacement_path, b"tampered replacement").unwrap();
        let before = fs::read(&target).unwrap();
        let error = overlay.apply_to_staging(&staging).unwrap_err();
        assert!(error.contains("curation replacement mismatch"));
        assert_eq!(fs::read(&target).unwrap(), before, "failure wrote target");
    }

    #[test]
    fn replacement_paths_reject_traversal_fixtures_and_non_json_targets() {
        for path in [
            "../registry/a.json",
            "/registry/a.json",
            "registry/../a.json",
            "registry/tests/a.json",
            "registry/a.tests.json",
            "registry/a.toml",
            "other/a.json",
            "registry\\a.json",
        ] {
            assert!(
                validate_repo_relative_path(path, true).is_err(),
                "unsafe path accepted: {path}"
            );
        }
        assert!(validate_repo_relative_path("registry/a/b.json", true).is_ok());
        assert!(validate_repo_relative_path("ercs/eip.json", true).is_ok());
    }

    #[test]
    fn replacement_inventory_rejects_unlisted_files_and_symlinks() {
        let temp = tempfile::tempdir().expect("create inventory test directory");
        let root = temp.path().join("files");
        let declared = "registry/example/a.json";
        fs::create_dir_all(root.join("registry/example")).unwrap();
        fs::write(root.join(declared), b"{}\n").unwrap();
        let replacement = one_replacement(declared, b"old", b"{}\n");
        assert!(verify_replacement_inventory(&root, std::slice::from_ref(&replacement)).is_ok());

        fs::write(root.join("registry/example/extra.json"), b"{}\n").unwrap();
        let error =
            verify_replacement_inventory(&root, std::slice::from_ref(&replacement)).unwrap_err();
        assert!(error.contains("inventory differs"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::remove_file(root.join("registry/example/extra.json")).unwrap();
            symlink(root.join(declared), root.join("registry/example/link.json")).unwrap();
            let error = verify_replacement_inventory(&root, &[replacement]).unwrap_err();
            assert!(error.contains("symlink is forbidden"));
        }
    }

    #[test]
    fn applied_diff_must_equal_the_declared_replacement_set() {
        let temp = tempfile::tempdir().expect("create diff-set test directory");
        let source = temp.path().join("source");
        let staging = temp.path().join("staging");
        let replacement_root = temp.path().join("overlay");
        let declared = "registry/example/a.json";
        let undeclared = "registry/example/b.json";
        for root in [&source, &staging, &replacement_root] {
            fs::create_dir_all(root.join("registry/example")).unwrap();
        }
        fs::write(source.join(declared), b"upstream-a").unwrap();
        fs::write(source.join(undeclared), b"upstream-b").unwrap();
        fs::write(staging.join(declared), b"curated-a").unwrap();
        fs::write(staging.join(undeclared), b"upstream-b").unwrap();
        fs::write(replacement_root.join(declared), b"curated-a").unwrap();
        let overlay = test_overlay(
            &replacement_root,
            one_replacement(declared, b"upstream-a", b"curated-a"),
        );
        let source_files = [source.join(declared), source.join(undeclared)]
            .into_iter()
            .collect();
        let staged_files = [staging.join(declared), staging.join(undeclared)]
            .into_iter()
            .collect();
        overlay
            .verify_applied_diff(&source, &source_files, &staging, &staged_files)
            .unwrap();

        fs::write(staging.join(undeclared), b"undeclared change").unwrap();
        let error = overlay
            .verify_applied_diff(&source, &source_files, &staging, &staged_files)
            .unwrap_err();
        assert!(error.contains("diff set differs from manifest"));
    }

    #[test]
    fn curated_corpus_rejects_unreceipted_top_level_entries() {
        let temp = tempfile::tempdir().expect("create curated-root fixture");
        let root = temp.path();
        fs::create_dir(root.join("registry")).unwrap();
        fs::create_dir(root.join("ercs")).unwrap();
        fs::write(root.join(VENDORED_MARKER_PATH), b"pinned\n").unwrap();
        fs::write(root.join(VENDORED_README_PATH), b"metadata\n").unwrap();
        assert!(collect_curated_corpus_files(root).is_ok());

        fs::write(root.join("planted.json"), b"{}\n").unwrap();
        let error = collect_curated_corpus_files(root).unwrap_err();
        assert!(error.contains("unexpected unreceipted"), "{error}");
        fs::remove_file(root.join("planted.json")).unwrap();

        fs::create_dir(root.join("specs")).unwrap();
        let error = collect_curated_corpus_files(root).unwrap_err();
        assert!(error.contains("unexpected unreceipted"), "{error}");
    }

    #[test]
    fn tool_input_tree_receipt_binds_inventory_bytes_and_file_types() {
        let temp = tempfile::tempdir().expect("create tool-input-tree fixture");
        let workspace = temp.path();
        let tree = workspace.join("crate/src");
        fs::create_dir_all(tree.join("nested")).unwrap();
        fs::write(tree.join("lib.rs"), b"mod nested;\n").unwrap();
        fs::write(tree.join("nested/mod.rs"), b"pub fn value() -> u8 { 1 }\n").unwrap();

        let files = collect_regular_tree_files(&tree).unwrap();
        let receipt = corpus_receipt(workspace, &files, TOOL_INPUT_TREE_DOMAIN.as_bytes()).unwrap();
        let identity = TreeIdentity {
            path: "crate/src".to_string(),
            domain: TOOL_INPUT_TREE_DOMAIN.to_string(),
            files: receipt.file_count as u64,
            bytes: receipt.byte_count,
            sha256: hex::encode(receipt.sha256),
        };
        verify_tree_identity(workspace, &identity, "test tree").unwrap();

        fs::write(tree.join("nested/mod.rs"), b"pub fn value() -> u8 { 2 }\n").unwrap();
        assert!(verify_tree_identity(workspace, &identity, "test tree")
            .unwrap_err()
            .contains("receipt mismatch"));
        fs::write(tree.join("nested/mod.rs"), b"pub fn value() -> u8 { 1 }\n").unwrap();

        fs::write(tree.join("added.dat"), b"bound include asset\n").unwrap();
        assert!(verify_tree_identity(workspace, &identity, "test tree")
            .unwrap_err()
            .contains("receipt mismatch"));
        fs::remove_file(tree.join("added.dat")).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(tree.join("lib.rs"), tree.join("link.rs")).unwrap();
            let error = verify_tree_identity(workspace, &identity, "test tree").unwrap_err();
            assert!(error.contains("symlink is forbidden"), "{error}");
        }
    }

    #[test]
    fn legacy_build_input_shadows_are_rejected_even_when_symlinked() {
        let temp = tempfile::tempdir().expect("create shadow-input fixture");
        let root = temp.path();
        fs::create_dir(root.join(".cargo")).unwrap();
        assert!(verify_shadow_inputs_absent(root).is_ok());

        for relative in FORBIDDEN_SHADOW_INPUT_PATHS {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"shadow\n").unwrap();
            let error = verify_shadow_inputs_absent(root).unwrap_err();
            assert!(error.contains("legacy build-input shadow"), "{error}");
            fs::remove_file(path).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.join("effective.toml");
            fs::write(&target, b"[env]\n").unwrap();
            let shadow = root.join(".cargo/config");
            symlink(&target, &shadow).unwrap();
            let error = verify_shadow_inputs_absent(root).unwrap_err();
            assert!(error.contains("legacy build-input shadow"), "{error}");
        }
    }

    #[test]
    fn checked_in_tool_tree_inventory_covers_output_construction_closure() {
        let required = [
            "dbgen/src/erc20.rs",
            "dbgen/src/erc7730.rs",
            "dbgen/src/lib.rs",
            "dbgen/src/merkle.rs",
            "pqsigner-erc7730/src/abi.rs",
            "pqsigner-erc7730/src/bundle.rs",
            "pqsigner-erc7730/src/display/primitives.rs",
            "pqsigner-erc7730/src/known_calls.rs",
            "pqsigner-erc7730/src/render/enums.rs",
            "pqsigner-erc7730/src/render/mod.rs",
            "pqsigner-erc7730/src/render/nested.rs",
            "pqsigner-erc7730/src/render/params.rs",
            "pqsigner-erc7730/src/render/policy.rs",
            "pqsigner-fi/src/lib.rs",
            "proto/src/lib.rs",
            "shared/src/db_format.rs",
            "shared/src/lib.rs",
            "tx-core/src/hash.rs",
            "tx-core/src/lib.rs",
            "tx/src/erc20/bundle.rs",
            "tx/src/erc20/merkle.rs",
            "tx/src/erc20/mod.rs",
            "tx/src/lib.rs",
            "tx/src/wire.rs",
            "xtask/src/erc7730_curation.rs",
            "xtask/src/main.rs",
        ];
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is one directory below workspace")
            .to_path_buf();
        let mut inventory = BTreeSet::new();
        for relative in TOOL_INPUT_TREE_PATHS {
            inventory.extend(
                collect_regular_tree_files(&workspace.join(relative))
                    .expect("collect checked-in tool tree")
                    .into_iter()
                    .map(|path| {
                        path_to_slash_string(path.strip_prefix(&workspace).unwrap()).unwrap()
                    }),
            );
        }
        for path in required {
            assert!(inventory.contains(path), "missing closure canary: {path}");
        }
    }

    #[test]
    #[ignore = "owner utility: print exact manifest-v2 input receipts after source freeze"]
    fn print_checked_in_manifest_v2_input_receipts() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is one directory below workspace")
            .to_path_buf();
        for relative in TOOL_INPUT_PATHS {
            let bytes = fs::read(workspace.join(relative)).unwrap();
            println!("FILE {relative} {}", hex::encode(Sha256::digest(bytes)));
        }
        for relative in TOOL_INPUT_TREE_PATHS {
            let files = collect_regular_tree_files(&workspace.join(relative)).unwrap();
            let receipt =
                corpus_receipt(&workspace, &files, TOOL_INPUT_TREE_DOMAIN.as_bytes()).unwrap();
            println!(
                "TREE {relative} {} {} {}",
                receipt.file_count,
                receipt.byte_count,
                hex::encode(receipt.sha256)
            );
        }
        for relative in CAPABILITY_INPUT_PATHS {
            let bytes = fs::read(workspace.join(relative)).unwrap();
            println!(
                "CAPABILITY {relative} {}",
                hex::encode(Sha256::digest(bytes))
            );
        }
    }

    #[test]
    fn checked_in_manifest_replacements_and_curated_corpus_are_exact() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is one directory below workspace")
            .to_path_buf();
        let manifest = workspace.join("secure/data/erc7730/curations/manifest.json");
        let overlay = VerifiedOverlay::load_and_verify_local_inputs(&workspace, &manifest)
            .expect("checked-in curation manifest and bound inputs");
        let receipt = overlay
            .verify_checked_in_tree(&workspace.join("secure/data/erc7730-registry"))
            .expect("checked-in curated corpus");
        assert_eq!(receipt.file_count, 387);
        assert_eq!(receipt.byte_count, 782_246);
        assert_eq!(overlay.replacement_count(), 34);
    }
}
