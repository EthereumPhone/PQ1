//! Binary IR for compiled ERC-7730 descriptors.
//!
//! The host pipeline (`dbgen::erc7730`) takes the registry JSON, runs
//! it through structural validation + JCS canonicalisation, records the
//! selected provenance policy, and emits one of these IR blobs per accepted
//! descriptor. The current full catalogue is explicitly `dev-unattested` and
//! production generation fails closed until real ERC-8176 verification lands.
//! The blobs are then Merkle-tree-hashed into
//! `ERC7730_DESCRIPTORS_ROOT`, pinned in `secure/src/db_roots.rs`.
//!
//! The on-device walker reads the IR with zero copies. All offsets are
//! into the IR's own metadata pool; no string parsing at sign time.
//!
//! ## Header (134 B fixed)
//!
//! ```text
//!   off  size  field
//!    0    1   schema_ver         (0x06 — see SCHEMA_VER)
//!    1    1   context_kind       (CTX_CONTRACT | CTX_EIP712)
//!    2    8   chain_id (u64 BE)  (for EIP-712: domain.chainId)
//!   10   20   contract           (for EIP-712: domain.verifyingContract)
//!   30   32   descriptor_hash    (sha256 of JCS-canonicalised source
//!                                 JSON; the host-only ERC-8176 identifier is
//!                                 a distinct keccak256 value)
//!   62   32   domain_separator   (EIP-712 only; zero for contract ctx)
//!   94   16   owner              (NUL-padded ASCII, ≤15 + NUL)
//!  110   16   contract_name      (NUL-padded ASCII, ≤15 + NUL)
//!  126    2   metadata_off       (u16 BE — pool start, ≥ HEADER_LEN)
//!  128    2   formats_off        (u16 BE — formats start, ≥ metadata_off)
//!  130    2   pool_len           (u16 BE — total metadata bytes)
//!  132    2   formats_len        (u16 BE — total format-table bytes)
//! ```
//!
//! After the header come the metadata pool, then the formats table.
//! Both are length-prefixed in the header so the walker can index
//! directly without re-parsing.
//!
//! ## Caps
//!
//! - 4 KiB per IR (covers 99% of registry by inspection; host pipeline
//!   rejects oversize)
//! - 32 formats per descriptor (MAX_FORMATS)
//! - 24 fields per format
//! - 8 path-program steps / nested EIP-712 struct levels; nested calldata is
//!   limited separately to one child level
//! - 256 B per individual pool entry
//!
//! Parsing is strict — any unknown opcode, unaligned offset, or
//! pool-out-of-range index returns `IrError::Malformed`.

use core::convert::TryFrom;

/// IR schema version. Bumped `0x01 → 0x02` when calldata `FieldIdx`
/// args changed meaning from *logical ordinals* to *ABI head-word slots*
/// (and a per-format `static_head_words` field was added to the format
/// header). Bumped `0x02 → 0x03` for the nested-EIP-712 struct renderer
/// (Phase 5): the format header gained a `nested_descent_count` pin (the
/// E1 reconciliation tripwire — see `docs/erc7730-nested-eip712-render-design.md`
/// §10), and `PARAM_NESTED_STRUCT` grew from a bare `[0x01]` belt marker to
/// a self-describing payload whose leading version byte selects bare-decline
/// (`0x01`) vs the structured v0x03 block (`0x03`). `parse` strict-rejects any
/// other value, so a descriptor compiled under the old, slot-confusable
/// encoding can never be walked by this firmware — and a 0x02 DB can never be
/// mixed-interpreted by 0x03 firmware. Bumped `0x03 → 0x04` for the mandatory
/// authenticated terminal-kind TLV on every field. Static path bytecode alone
/// cannot distinguish an address from uint/int/bool/bytesN; v4 lets the device
/// independently enforce the same exhaustive formatter/type/parameter matrix
/// as dbgen. Firmware + DB ship together under one pinned Merkle root, so old
/// v3 leaves hard-refuse instead of being mixed-interpreted.
/// Bumped `0x04 -> 0x05` to authenticate the original ABI integer width on
/// every signed/unsigned terminal. Firmware can now reject non-canonical zero
/// or sign extension instead of silently displaying a dirty narrow word as a
/// different full-width integer. Old v4 leaves hard-refuse because omitting
/// this width changes the accepted meaning of the same 32-byte word.
/// Bumped `0x05 -> 0x06` for exact authenticated EIP-712 string preimages. The
/// format header gained an independent `string_preimage_count` reconciliation
/// pin, and marked fields gained a distinct terminal kind plus ordered evidence
/// ordinal. Old v5 leaves hard-refuse rather than treating a signed string hash
/// word as calldata or as directly displayable text.
/// See `docs/security/vulns/VULN-erc7730-walker-slot-confusion.md`.
pub const SCHEMA_VER: u8 = 0x06;
pub const HEADER_LEN: usize = 134;

/// Upper bound on a nested EIP-712 struct's own member count (the number
/// of 32-byte words in ITS `encodeData`). Bounds `addr_word_bmp` size
/// (`ceil(member_count/8)` ≤ 4 B) and keeps the Kani binding-verifier
/// harness tractable. Permit2's structs have ≤4 members; leave headroom.
pub const MAX_NESTED_MEMBERS: usize = 32;

/// Upper bound on the element count of a nested EIP-712 array-of-struct member
/// (`T[]`, v2). Bounds the device's page budget — each element renders its
/// visible sub-fields plus a divider, and the whole array must fit inside
/// `MAX_PAGES` after the banner/chain/confirm pages — and the collect-verify
/// buffer. `elem_count > MAX_NESTED_ARRAY` (or `== 0`) declines. Introduced by
/// schema v4 and retained unchanged by schema v6.
pub const MAX_NESTED_ARRAY: usize = 6;

/// Maximum exact EIP-712 string preimages consumed by one format. This is a
/// format-authenticated reconciliation count, not a host-selected capacity.
pub const MAX_EIP712_STRING_PREIMAGES: usize = 2;

pub const CTX_CONTRACT: u8 = 0x01;
pub const CTX_EIP712: u8 = 0x02;

pub const MAX_IR_LEN: usize = 4096;
pub const MAX_FORMATS: usize = 32;
pub const MAX_FIELDS_PER_FORMAT: usize = 24;
/// Maximum path-program steps and nested EIP-712 struct depth. Nested calldata
/// has its own one-child, no-recursion policy.
pub const MAX_NESTING: usize = 8;
pub const MAX_POOL_ENTRY_LEN: usize = 256;

/// ERC-20 `approve(address,uint256)`. The host compiler does not enroll an
/// interpolated confirm banner for this authority-bearing selector; the device
/// mirrors that policy so a hostile authenticated IR cannot reintroduce it.
pub const ERC20_APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5E, 0xA7, 0xB3];

/// The first packed-path capability is deliberately deployment-scoped. These
/// constants are device-side belts behind dbgen's descriptor-hash enrollment;
/// a selector collision at any other address remains ordinary unsupported C2.
pub const UNISWAP_ROUTER02_CHAIN_ID: u64 = 1;
pub const UNISWAP_ROUTER02_MAINNET: [u8; 20] = [
    0x68, 0xb3, 0x46, 0x58, 0x33, 0xfb, 0x72, 0xa7, 0x0e, 0xcd, 0xf4, 0x85, 0xe0, 0xe4, 0xc7, 0xbd,
    0x86, 0x65, 0xfc, 0x45,
];
pub const UNISWAP_V3_EXACT_INPUT_SELECTOR: [u8; 4] = [0xb8, 0x58, 0x18, 0x3f];
pub const UNISWAP_V3_EXACT_OUTPUT_SELECTOR: [u8; 4] = [0x09, 0xb8, 0x13, 0x46];

pub const OWNER_FIELD_LEN: usize = 16;
pub const CONTRACT_NAME_FIELD_LEN: usize = 16;

/// Errors surfaced when parsing or walking an IR blob. Distinct kinds
/// help the secure-side caller emit a useful `ui::show_status` line
/// without leaking the full malformed-blob position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrError {
    /// Blob too small for the fixed header.
    TooShort,
    /// Blob too large for the on-device walker.
    TooLarge,
    /// Unknown `schema_ver` — refuse rather than guess.
    SchemaVersion,
    /// `context_kind` outside the small known set.
    BadContextKind,
    /// Pool / formats offsets or lengths inconsistent.
    BadLayout,
    /// Pool entry header malformed (bad kind / oversize / truncated).
    BadPoolEntry,
    /// Format entry malformed (bad selector / field count / truncated).
    BadFormat,
    /// Field entry malformed (bad opcode / pool index out of range).
    BadField,
    /// ASCII-required string carries a non-printable byte.
    BadAscii,
    /// Some cap (MAX_*) exceeded.
    OverCap,
}

/// Discriminator for the descriptor's binding context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKind {
    /// Smart-contract calldata. `chain_id` + `contract` MUST match the
    /// signed transaction's `chain_id` + `to`.
    Contract,
    /// EIP-712 typed-data. `chain_id` + `contract` MUST match the
    /// payload's `domain.chainId` + `domain.verifyingContract`. The
    /// 32 B `domain_separator` further binds `name`/`version` etc.
    Eip712,
}

impl TryFrom<u8> for ContextKind {
    type Error = IrError;
    fn try_from(b: u8) -> Result<Self, IrError> {
        match b {
            CTX_CONTRACT => Ok(ContextKind::Contract),
            CTX_EIP712 => Ok(ContextKind::Eip712),
            _ => Err(IrError::BadContextKind),
        }
    }
}

/// Parsed (zero-copy) view of an IR blob. All slices borrow from the
/// caller-supplied `bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Erc7730Ir<'a> {
    pub schema_ver: u8,
    pub context_kind: ContextKind,
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub descriptor_hash: [u8; 32],
    pub domain_separator: [u8; 32],
    /// Trimmed ASCII (no trailing NULs). May be empty.
    pub owner: &'a [u8],
    /// Trimmed ASCII (no trailing NULs). May be empty.
    pub contract_name: &'a [u8],
    /// Raw pool bytes — interpreted lazily by the walker.
    pub pool: &'a [u8],
    /// Raw formats-table bytes — interpreted lazily by the walker.
    pub formats: &'a [u8],
    /// Original full blob (used to recompute the leaf hash for Merkle
    /// verification without holding a separate cursor).
    pub raw: &'a [u8],
}

/// Path-bytecode opcodes. The metadata pool stores compiled paths as
/// sequences of (opcode + arg-bytes) tuples. See the layout comment in
/// `lib.rs` and the walker for full semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathOp {
    /// `#` — root: structured data (ABI-decoded calldata head).
    RootStructured = 0x10,
    /// `@` — root: container (tx / EIP-712 envelope).
    RootContainer = 0x11,
    /// `$` — root: descriptor metadata pool.
    RootMetadata = 0x12,
    /// `.<field>` — by field index into the ABI shape table.
    FieldIdx = 0x20,
    /// `[idx]` — array index (2 B BE; the op is 3 bytes in all).
    ArrayIdx = 0x21,
    /// `[start:end]` / `[-len:]` — slice: 2 B BE start, 2 B BE len, 1 B
    /// `from_end` flag (the op is 6 bytes in all).
    ArraySlice = 0x22,
    /// `[-1]` — last element of an array.
    ArrayLast = 0x23,
    /// `[]` — whole array iteration.
    ArrayAll = 0x24,
    /// Follow the ABI offset word at the current position into the calldata
    /// tail (dynamic arg / dynamic tuple / dynamic leaf). See
    /// `render::resolve::resolve_structured`. A reserved op like `ArrayAll`:
    /// firmware that predates it declines-to-blind rather than mis-reads.
    FollowOffset = 0x25,
}

impl TryFrom<u8> for PathOp {
    type Error = IrError;
    fn try_from(b: u8) -> Result<Self, IrError> {
        match b {
            0x10 => Ok(PathOp::RootStructured),
            0x11 => Ok(PathOp::RootContainer),
            0x12 => Ok(PathOp::RootMetadata),
            0x20 => Ok(PathOp::FieldIdx),
            0x21 => Ok(PathOp::ArrayIdx),
            0x22 => Ok(PathOp::ArraySlice),
            0x23 => Ok(PathOp::ArrayLast),
            0x24 => Ok(PathOp::ArrayAll),
            0x25 => Ok(PathOp::FollowOffset),
            _ => Err(IrError::BadField),
        }
    }
}

/// Formatter opcodes (the `format:` JSON field). The display layer in
/// `secure/src/tx/display/erc7730/formatters.rs` provides one renderer
/// per opcode. Values are stable wire constants — DO NOT renumber after
/// the first firmware that pins a Merkle root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FormatOp {
    Raw = 0x01,
    Amount = 0x02,
    TokenAmount = 0x03,
    NftName = 0x04,
    Date = 0x05,
    Duration = 0x06,
    AddressName = 0x07,
    Enum = 0x08,
    Unit = 0x09,
    Calldata = 0x0A,
    ChainId = 0x0B,
    TokenTicker = 0x0C,
    InteroperableAddressName = 0x0D,
    Encrypted = 0x0E,
    /// PQSigner-authenticated rendering of the complete Uniswap V3 packed
    /// `token(20) | fee(3) | token(20) ...` path. Admission is additionally
    /// restricted to exact Router02 semantic enrollments by dbgen and the
    /// contract-calldata preflight; this is not a generic dynamic-bytes
    /// formatter.
    UniswapV3Path = 0x0F,
}

impl FormatOp {
    /// Complete stable wire vocabulary, in opcode order.  Code generation and
    /// semantic-documentation guards iterate this array instead of maintaining
    /// a second list that can silently swap entries (notably `NftName = 0x04`
    /// and `Unit = 0x09`).
    pub const ALL: [Self; 15] = [
        Self::Raw,
        Self::Amount,
        Self::TokenAmount,
        Self::NftName,
        Self::Date,
        Self::Duration,
        Self::AddressName,
        Self::Enum,
        Self::Unit,
        Self::Calldata,
        Self::ChainId,
        Self::TokenTicker,
        Self::InteroperableAddressName,
        Self::Encrypted,
        Self::UniswapV3Path,
    ];

    /// ERC-7730 JSON spelling compiled to this wire opcode.
    #[must_use]
    pub const fn registry_name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Amount => "amount",
            Self::TokenAmount => "tokenAmount",
            Self::NftName => "nftName",
            Self::Date => "date",
            Self::Duration => "duration",
            Self::AddressName => "addressName",
            Self::Enum => "enum",
            Self::Unit => "unit",
            Self::Calldata => "calldata",
            Self::ChainId => "chainId",
            Self::TokenTicker => "tokenTicker",
            Self::InteroperableAddressName => "interoperableAddressName",
            Self::Encrypted => "encrypted",
            Self::UniswapV3Path => "uniswapV3Path",
        }
    }
}

impl TryFrom<u8> for FormatOp {
    type Error = IrError;
    fn try_from(b: u8) -> Result<Self, IrError> {
        match b {
            0x01 => Ok(FormatOp::Raw),
            0x02 => Ok(FormatOp::Amount),
            0x03 => Ok(FormatOp::TokenAmount),
            0x04 => Ok(FormatOp::NftName),
            0x05 => Ok(FormatOp::Date),
            0x06 => Ok(FormatOp::Duration),
            0x07 => Ok(FormatOp::AddressName),
            0x08 => Ok(FormatOp::Enum),
            0x09 => Ok(FormatOp::Unit),
            0x0A => Ok(FormatOp::Calldata),
            0x0B => Ok(FormatOp::ChainId),
            0x0C => Ok(FormatOp::TokenTicker),
            0x0D => Ok(FormatOp::InteroperableAddressName),
            0x0E => Ok(FormatOp::Encrypted),
            0x0F => Ok(FormatOp::UniswapV3Path),
            _ => Err(IrError::BadField),
        }
    }
}

/// Visibility rules from the spec. `MustMatch` differs from `Never` in
/// that the walker MUST evaluate the value and reject the whole
/// descriptor if the value isn't in the allow list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Visibility {
    Always = 0x00,
    Never = 0x01,
    Optional = 0x02,
    IfNotIn = 0x03,
    MustMatch = 0x04,
}

impl TryFrom<u8> for Visibility {
    type Error = IrError;
    fn try_from(b: u8) -> Result<Self, IrError> {
        match b {
            0x00 => Ok(Visibility::Always),
            0x01 => Ok(Visibility::Never),
            0x02 => Ok(Visibility::Optional),
            0x03 => Ok(Visibility::IfNotIn),
            0x04 => Ok(Visibility::MustMatch),
            _ => Err(IrError::BadField),
        }
    }
}

impl<'a> Erc7730Ir<'a> {
    /// Parse the fixed header, locate the pool/formats sections, and deeply
    /// validate the complete authenticated format table before returning.
    ///
    /// Reject blobs that:
    /// * are shorter than `HEADER_LEN`
    /// * are larger than `MAX_IR_LEN`
    /// * carry an unknown `schema_ver`
    /// * carry an unknown `context_kind`
    /// * declare pool/formats offsets that overlap or extend past EOF
    /// * carry non-printable bytes in the `owner` / `contract_name`
    ///   slots (anti-spoof: a hostile descriptor must not sneak
    ///   homoglyphs onto the trusted display)
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IrError> {
        Self::parse_with_nested_calldata_enrollments(
            bytes,
            crate::render::calldata_policy::ACTIVE_NESTED_CALLDATA_ENROLLMENTS,
        )
    }

    /// Internal test seam for the exact synthetic nested-calldata policy row.
    /// Production callers cannot supply host-selected policy: [`parse`](Self::parse)
    /// always uses the firmware-owned production table above.
    pub(crate) fn parse_with_nested_calldata_enrollments(
        bytes: &'a [u8],
        nested_calldata_enrollments: &[crate::render::calldata_policy::NestedCalldataEnrollment],
    ) -> Result<Self, IrError> {
        if bytes.len() > MAX_IR_LEN {
            return Err(IrError::TooLarge);
        }
        if bytes.len() < HEADER_LEN {
            return Err(IrError::TooShort);
        }

        let schema_ver = bytes[0];
        if schema_ver != SCHEMA_VER {
            return Err(IrError::SchemaVersion);
        }
        let context_kind = ContextKind::try_from(bytes[1])?;

        let chain_id = u64::from_be_bytes(bytes[2..10].try_into().map_err(|_| IrError::BadLayout)?);

        let mut contract = [0u8; 20];
        contract.copy_from_slice(&bytes[10..30]);

        let mut descriptor_hash = [0u8; 32];
        descriptor_hash.copy_from_slice(&bytes[30..62]);

        let mut domain_separator = [0u8; 32];
        domain_separator.copy_from_slice(&bytes[62..94]);

        if matches!(context_kind, ContextKind::Contract) && domain_separator != [0u8; 32] {
            // Contract context MUST NOT carry a non-zero domain
            // separator. Forbid it so a hostile descriptor can't
            // pretend to be both.
            return Err(IrError::BadLayout);
        }

        let owner = trim_nul(&bytes[94..94 + OWNER_FIELD_LEN])?;
        let contract_name = trim_nul(&bytes[110..110 + CONTRACT_NAME_FIELD_LEN])?;

        let metadata_off = u16::from_be_bytes([bytes[126], bytes[127]]) as usize;
        let formats_off = u16::from_be_bytes([bytes[128], bytes[129]]) as usize;
        let pool_len = u16::from_be_bytes([bytes[130], bytes[131]]) as usize;
        let formats_len = u16::from_be_bytes([bytes[132], bytes[133]]) as usize;

        // Layout invariants. The pool starts at the end of the fixed
        // header; the formats section starts at the end of the pool.
        // Both sections must fit inside `bytes`.
        if metadata_off != HEADER_LEN {
            return Err(IrError::BadLayout);
        }
        if formats_off != metadata_off + pool_len {
            return Err(IrError::BadLayout);
        }
        let total = formats_off
            .checked_add(formats_len)
            .ok_or(IrError::BadLayout)?;
        if total != bytes.len() {
            return Err(IrError::BadLayout);
        }

        let pool = &bytes[metadata_off..metadata_off + pool_len];
        let formats = &bytes[formats_off..formats_off + formats_len];

        let ir = Erc7730Ir {
            schema_ver,
            context_kind,
            chain_id,
            contract,
            descriptor_hash,
            domain_separator,
            owner,
            contract_name,
            pool,
            formats,
            raw: bytes,
        };
        // Verification authenticates the entire leaf, so validation must also
        // cover the entire leaf. A first-match selector must not make a
        // malformed/duplicate suffix unreachable, and the advertised caps must
        // be enforced before any renderer consumes the IR.
        ir.validate_formats(nested_calldata_enrollments)?;
        Ok(ir)
    }

    /// Number of formats declared in the formats section. Reads the
    /// 1-byte count prefix; returns 0 on an empty section. Bounded by
    /// `MAX_FORMATS`.
    pub fn format_count(&self) -> Result<u8, IrError> {
        if self.formats.is_empty() {
            return Ok(0);
        }
        let n = self.formats[0];
        if (n as usize) > MAX_FORMATS {
            return Err(IrError::OverCap);
        }
        Ok(n)
    }

    /// Iterate parsed format headers. Each yielded item carries the
    /// 4-byte selector / typehash-prefix, the human-readable intent
    /// string, and the bytes of the format's field-table (consumable
    /// via [`FormatHeader::fields`]).
    ///
    /// Use [`find_format_by_selector`](Self::find_format_by_selector)
    /// to pick the format that matches an inbound calldata 4-byte
    /// selector or EIP-712 primary-type-hash prefix.
    pub fn format_iter(&self) -> FormatIter<'a> {
        // The format-count prefix is the very first byte; bail to an
        // empty iterator if the section is malformed enough that we
        // can't even read it. The walker / caller can re-derive the
        // count via `format_count()` if it needs to distinguish the
        // empty case from the malformed case.
        let cursor = if self.formats.is_empty() { 0 } else { 1 };
        let count = if self.formats.is_empty() {
            0
        } else {
            self.formats[0]
        };
        FormatIter {
            buf: self.formats,
            cursor,
            remaining: count,
            is_eip712: matches!(self.context_kind, ContextKind::Eip712),
        }
    }

    /// Fetch the bytes of a path program at `path_off` inside the metadata
    /// pool. The first pool byte at `path_off` is the program length; the
    /// returned slice covers the opcodes that follow. `path_off == 0` is the
    /// "no path" sentinel and returns an empty slice (the caller decides
    /// whether that is acceptable for its formatter context).
    ///
    /// Lives here (not the legacy `walker`) because the live render path reads
    /// path programs directly — this is the one accessor it shares with the
    /// legacy interpreter (review 5.4).
    pub fn path_bytes(&self, path_off: u16) -> Result<&'a [u8], IrError> {
        if path_off == 0 {
            return Ok(&[]);
        }
        let off = path_off as usize;
        let len = *self.pool.get(off).ok_or(IrError::BadField)? as usize;
        self.pool
            .get(off + 1..off + 1 + len)
            .ok_or(IrError::BadField)
    }

    /// Locate the format whose 4-byte selector / typehash-prefix
    /// matches `selector`. Returns `Ok(None)` if no format matches —
    /// the secure-side caller renders that as "no clear-signing
    /// descriptor for this function".
    ///
    /// Returns an `IrError` only when the formats section itself is
    /// malformed (truncated header, oversized field count, …); a
    /// missing match is `Ok(None)`.
    pub fn find_format_by_selector(
        &self,
        selector: &[u8; 4],
    ) -> Result<Option<FormatHeader<'a>>, IrError> {
        for entry in self.format_iter() {
            let header = entry?;
            if &header.selector == selector {
                return Ok(Some(header));
            }
        }
        Ok(None)
    }

    /// Deep structural validation of the complete format table. Kept stack-only
    /// and allocation-free for secure-world use.
    fn validate_formats(
        &self,
        nested_calldata_enrollments: &[crate::render::calldata_policy::NestedCalldataEnrollment],
    ) -> Result<(), IrError> {
        let declared = self.format_count()? as usize;
        let mut iter = self.format_iter();
        let mut seen = 0usize;
        while let Some(entry) = iter.next() {
            let header = entry?;
            seen += 1;
            if matches!(self.context_kind, ContextKind::Eip712)
                && header.selector != header.type_hash[..4]
            {
                return Err(IrError::BadFormat);
            }
            if header.string_preimage_count as usize > MAX_EIP712_STRING_PREIMAGES {
                return Err(IrError::OverCap);
            }
            let mut fields = header.fields();
            let mut field_ordinal = 0u8;
            let mut interpolated_intent = None;
            let mut actual_nested_descents = 0u8;
            let mut saw_bare_nested_marker = false;
            let mut packed_v3_path_fields = 0u8;
            let mut exact_empty_bytes_fields = 0u8;
            let mut actual_string_preimages = 0u8;
            let mut calldata_fields = 0u8;
            let mut dynamic_value_paths = 0u8;
            let mut has_dynamic_tail_topology = false;
            let packed_v3_identity = is_uniswap_router02_packed_identity(self, &header);
            while let Some(field) = fields.next() {
                let field = field?;
                let op = FormatOp::try_from(field.format_op)?;
                if op == FormatOp::UniswapV3Path {
                    packed_v3_path_fields = packed_v3_path_fields
                        .checked_add(1)
                        .ok_or(IrError::OverCap)?;
                }
                if field.path_off != 0 {
                    let path = self.path_bytes(field.path_off)?;
                    validate_path_program(path)?;
                }
                if field.param_off == 0 {
                    // Schema v6 requires the authenticated terminal-kind TLV
                    // even when a formatter has no other parameters. Integer
                    // kinds additionally require their authenticated width.
                    return Err(IrError::BadField);
                }
                validate_pool_entry(self.pool, field.param_off)?;
                let params = crate::render::params::parse(self, field.param_off)
                    .map_err(|_| IrError::BadPoolEntry)?;
                let kind = params.terminal_kind.ok_or(IrError::BadField)?;

                if let Some(topology) = params.dynamic_tail_topology.as_ref() {
                    // The topology is format-level signing authority with one
                    // canonical location. It is never a field-local semantic
                    // parameter and is unavailable to EIP-712/nested fields.
                    if field_ordinal != 0
                        || has_dynamic_tail_topology
                        || !matches!(self.context_kind, ContextKind::Contract)
                    {
                        return Err(IrError::BadFormat);
                    }
                    topology
                        .validate_static_head(header.static_head_words)
                        .map_err(|_| IrError::BadFormat)?;
                    has_dynamic_tail_topology = true;
                }

                if field.path_off != 0
                    && self.path_bytes(field.path_off)?.last().copied()
                        == Some(PathOp::FollowOffset as u8)
                {
                    dynamic_value_paths =
                        dynamic_value_paths.checked_add(1).ok_or(IrError::OverCap)?;
                }

                if validate_eip712_string_preimage_field(
                    self,
                    &header,
                    &field,
                    op,
                    kind,
                    &params,
                    actual_string_preimages,
                )? {
                    actual_string_preimages = actual_string_preimages
                        .checked_add(1)
                        .ok_or(IrError::OverCap)?;
                }

                validate_word_guard(self, &field, kind, &params, packed_v3_identity)?;
                if validate_exact_empty_bytes_field(self, &header, &field, op, kind, &params)? {
                    exact_empty_bytes_fields = exact_empty_bytes_fields
                        .checked_add(1)
                        .ok_or(IrError::OverCap)?;
                    if exact_empty_bytes_fields > 1 {
                        return Err(IrError::BadFormat);
                    }
                }

                if params.visibility != Visibility::Never
                    && !crate::render::policy::label_has_visible_glyph(field.label)
                {
                    return Err(IrError::BadAscii);
                }

                if let Some(program) = params.interpolated_intent {
                    // This is format-level state with one canonical wire
                    // location. A second location or a later field would
                    // create order-dependent meaning.
                    if field_ordinal != 0
                        || interpolated_intent.replace(program).is_some()
                        || !matches!(self.context_kind, ContextKind::Contract)
                    {
                        return Err(IrError::BadFormat);
                    }
                }

                if let Some(payload) = params.nested_struct {
                    match payload.first().copied() {
                        Some(0x01) if payload.len() == 1 => {
                            // Legacy belt marker remains an intentional hard
                            // refusal.  Validate the underlying field normally,
                            // but never count the marker as a structured descent.
                            saw_bare_nested_marker = true;
                            let mask = params
                                .policy_mask()
                                .without(crate::render::policy::ParamMask::NESTED_STRUCT);
                            crate::render::policy::validate_field(op, kind, mask)
                                .map_err(|_| IrError::BadField)?;
                            validate_terminal_path_shape(self, &field, kind, &params, false)?;
                        }
                        Some(crate::render::nested::NESTED_V3) => {
                            if !matches!(self.context_kind, ContextKind::Eip712)
                                || op != FormatOp::Raw
                                || kind != crate::render::policy::TerminalKind::NestedStruct
                                || field.path_off != 0
                            {
                                return Err(IrError::BadField);
                            }
                            reject_nested_dynamic_tail_topology(self, payload, 1)?;
                            crate::render::policy::validate_field(op, kind, params.policy_mask())
                                .map_err(|_| IrError::BadField)?;
                            let consumed = crate::render::nested::validate_nested_ir(
                                self,
                                payload,
                                header.static_head_words as usize,
                                1,
                            )?;
                            actual_nested_descents = actual_nested_descents
                                .checked_add(consumed)
                                .ok_or(IrError::OverCap)?;
                        }
                        _ => return Err(IrError::BadPoolEntry),
                    }
                } else {
                    if kind == crate::render::policy::TerminalKind::NestedStruct {
                        return Err(IrError::BadField);
                    }
                    crate::render::policy::validate_field(op, kind, params.policy_mask())
                        .map_err(|_| IrError::BadField)?;
                    validate_terminal_path_shape(self, &field, kind, &params, true)?;
                }

                if op == FormatOp::Calldata {
                    validate_nested_calldata_field(
                        self,
                        &header,
                        &field,
                        field_ordinal,
                        kind,
                        &params,
                        nested_calldata_enrollments,
                    )?;
                    calldata_fields = calldata_fields.checked_add(1).ok_or(IrError::OverCap)?;
                }

                if op == FormatOp::Enum {
                    let enum_off = params.enum_ref.ok_or(IrError::BadField)?;
                    crate::render::enums::validate_enum_table(self.pool, enum_off)
                        .map_err(|_| IrError::BadPoolEntry)?;
                }
                field_ordinal = field_ordinal.checked_add(1).ok_or(IrError::OverCap)?;
            }
            if fields.cursor() != header.fields_buf.len() {
                return Err(IrError::BadFormat);
            }
            validate_uniswap_v3_format(self, &header, packed_v3_path_fields, packed_v3_identity)?;
            let parent_key = crate::render::calldata_policy::NestedCalldataParentKey {
                descriptor_hash: &self.descriptor_hash,
                chain_id: self.chain_id,
                parent_contract: &self.contract,
                parent_selector: &header.selector,
            };
            let parent_enrolled = crate::render::calldata_policy::lookup_parent(
                nested_calldata_enrollments,
                parent_key,
            )
            .map_err(|_| IrError::BadFormat)?
            .is_some();
            if (calldata_fields > 0
                && (calldata_fields != 1 || !has_dynamic_tail_topology && dynamic_value_paths != 1))
                || parent_enrolled != (calldata_fields == 1)
            {
                return Err(IrError::BadFormat);
            }
            if let Some(program) = interpolated_intent {
                // Belt behind `InterpolatedIntentProgram::parse`: the current
                // executable subset is exactly one substitution followed by
                // an empty final literal. Keep this check in the enclosing
                // format validator so faulted parser state cannot broaden the
                // confirm-banner authority boundary.
                if program.substitution_count() != 1
                    || !program
                        .literal(1)
                        .map_err(|_| IrError::BadPoolEntry)?
                        .is_empty()
                    || header.selector == ERC20_APPROVE_SELECTOR
                {
                    return Err(IrError::BadFormat);
                }
                let mut token_amount_refs = 0u8;
                for slot in 0..program.substitution_count() {
                    let ordinal = program
                        .field_ordinal(slot)
                        .map_err(|_| IrError::BadPoolEntry)?;
                    if ordinal >= header.field_count {
                        return Err(IrError::BadFormat);
                    }
                    let target = header
                        .fields()
                        .nth(ordinal as usize)
                        .ok_or(IrError::BadFormat)??;
                    let op = FormatOp::try_from(target.format_op)?;
                    if !matches!(op, FormatOp::Amount | FormatOp::TokenAmount) {
                        return Err(IrError::BadFormat);
                    }
                    if matches!(op, FormatOp::TokenAmount) {
                        token_amount_refs =
                            token_amount_refs.checked_add(1).ok_or(IrError::OverCap)?;
                        if token_amount_refs > 1 {
                            return Err(IrError::BadFormat);
                        }
                    }
                    let target_params = crate::render::params::parse(self, target.param_off)
                        .map_err(|_| IrError::BadPoolEntry)?;
                    if target_params.visibility != Visibility::Always
                        || target_params.threshold.is_some()
                        || target_params.message.is_some()
                    {
                        return Err(IrError::BadFormat);
                    }
                    let path = self.path_bytes(target.path_off)?;
                    validate_interpolated_scalar_path(path)?;
                }
            }
            if actual_nested_descents != header.nested_descent_count
                || saw_bare_nested_marker && actual_nested_descents != 0
                || matches!(self.context_kind, ContextKind::Contract)
                    && header.nested_descent_count != 0
                || actual_string_preimages != header.string_preimage_count
                || matches!(self.context_kind, ContextKind::Contract)
                    && header.string_preimage_count != 0
            {
                return Err(IrError::BadFormat);
            }
        }
        if seen != declared || iter.remaining != 0 || iter.cursor != self.formats.len() {
            return Err(IrError::BadFormat);
        }

        // Selectors are canonical and unique. O(MAX_FORMATS²) is bounded at
        // 32×32 and avoids heap storage in the secure parser.
        let mut outer = self.format_iter();
        let mut outer_idx = 0usize;
        while let Some(entry) = outer.next() {
            let lhs = entry?;
            let mut inner = self.format_iter();
            let mut inner_idx = 0usize;
            while let Some(other) = inner.next() {
                let rhs = other?;
                if inner_idx > outer_idx && lhs.selector == rhs.selector {
                    return Err(IrError::BadFormat);
                }
                inner_idx += 1;
            }
            outer_idx += 1;
        }
        Ok(())
    }
}

/// Reject the contract-only format topology marker from every nested EIP-712
/// sub-field, including descendants. Nested parameter blobs are parsed by the
/// shared TLV parser and the marker is intentionally absent from field policy,
/// so the enclosing deep validator must make this authority boundary explicit
/// instead of allowing an inert second wire spelling.
fn reject_nested_dynamic_tail_topology(
    ir: &Erc7730Ir<'_>,
    payload: &[u8],
    depth: usize,
) -> Result<(), IrError> {
    if depth == 0 || depth > MAX_NESTING {
        return Err(IrError::OverCap);
    }
    let nested = crate::render::nested::parse_nested_struct_param(payload)
        .map_err(|_| IrError::BadPoolEntry)?;
    for field in nested.sub_fields() {
        let field = field?;
        let params =
            crate::render::params::parse(ir, field.param_off).map_err(|_| IrError::BadPoolEntry)?;
        if params.dynamic_tail_topology.is_some() {
            return Err(IrError::BadFormat);
        }
        if let Some(child) = params.nested_struct {
            if child.first() == Some(&crate::render::nested::NESTED_V3) {
                reject_nested_dynamic_tail_topology(ir, child, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// Validate the schema-v6 authority to replace one signed EIP-712 string-hash
/// word with a separately supplied exact preimage.
///
/// The marker is deliberately a top-level static-word capability: the path is
/// exactly `RootStructured / FieldIdx(slot)`, the slot is inside the
/// authenticated member count, and marker ordinals are the canonical
/// `0..string_preimage_count` sequence in visible-field traversal order. This
/// function authenticates only the IR topology; runtime code must still hash
/// the complete evidence bytes and compare all 32 committed bytes before any
/// page is published.
fn validate_eip712_string_preimage_field(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    field: &FieldEntry<'_>,
    op: FormatOp,
    kind: crate::render::policy::TerminalKind,
    params: &crate::render::params::ParamSet<'_>,
    expected_ordinal: u8,
) -> Result<bool, IrError> {
    use crate::render::policy::TerminalKind;

    let Some(ordinal) = params.eip712_string_preimage_ordinal else {
        return if kind == TerminalKind::Eip712StringHashWord {
            Err(IrError::BadField)
        } else {
            Ok(false)
        };
    };

    if !matches!(ir.context_kind, ContextKind::Eip712)
        || params.visibility != Visibility::Always
        || op != FormatOp::Raw
        || kind != TerminalKind::Eip712StringHashWord
        || params.dynamic_kind.is_some()
        || field.path_off == 0
        || ordinal != expected_ordinal
        || ordinal >= format.string_preimage_count
        || ordinal as usize >= MAX_EIP712_STRING_PREIMAGES
    {
        return Err(IrError::BadField);
    }

    let path = ir.path_bytes(field.path_off)?;
    if path.len() != 4
        || path[0] != PathOp::RootStructured as u8
        || path[1] != PathOp::FieldIdx as u8
    {
        return Err(IrError::BadField);
    }
    let slot = u16::from_be_bytes([path[2], path[3]]);
    if slot >= format.static_head_words {
        return Err(IrError::BadField);
    }
    Ok(true)
}

/// Validate the narrow authenticated authority carried by
/// `PARAM_EXACT_EMPTY_BYTES` before any format can reach the renderer.
///
/// The marker belongs only to one always-visible `Callback` field in a
/// contract-call format. Its path must be the exact top-level C1 program
/// `RootStructured / FieldIdx(slot) / FollowOffset`, and the named offset word
/// must lie inside the authenticated static head. Runtime framing separately
/// binds that offset to the head end and requires an exact zero-length EOF
/// tail.
fn validate_exact_empty_bytes_field(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    field: &FieldEntry<'_>,
    op: FormatOp,
    kind: crate::render::policy::TerminalKind,
    params: &crate::render::params::ParamSet<'_>,
) -> Result<bool, IrError> {
    use crate::render::{params::DYNAMIC_KIND_BYTES, policy::TerminalKind};

    if !params.exact_empty_bytes {
        return Ok(false);
    }
    if !matches!(ir.context_kind, ContextKind::Contract)
        || params.visibility != Visibility::Always
        || op != FormatOp::Raw
        || kind != TerminalKind::DynamicBytes
        || params.dynamic_kind != Some(DYNAMIC_KIND_BYTES)
        || field.label != b"Callback"
        || field.path_off == 0
    {
        return Err(IrError::BadField);
    }
    let path = ir.path_bytes(field.path_off)?;
    if path.len() != 5
        || path[0] != PathOp::RootStructured as u8
        || path[1] != PathOp::FieldIdx as u8
        || path[4] != PathOp::FollowOffset as u8
    {
        return Err(IrError::BadField);
    }
    let slot = u16::from_be_bytes([path[2], path[3]]);
    if slot >= format.static_head_words {
        return Err(IrError::BadField);
    }
    Ok(true)
}

/// Device-side mirror of dbgen's exact nested-calldata admission.
///
/// This validates only authenticated IR topology and firmware policy. Runtime
/// N3 binding still has to resolve the callee word canonically, derive the
/// child selector from the signed bytes, and prove the child descriptor.
fn validate_nested_calldata_field(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    field: &FieldEntry<'_>,
    field_ordinal: u8,
    kind: crate::render::policy::TerminalKind,
    params: &crate::render::params::ParamSet<'_>,
    enrollments: &[crate::render::calldata_policy::NestedCalldataEnrollment],
) -> Result<(), IrError> {
    use crate::render::{
        calldata_policy::{
            calldata_field_slot, callee_location, lookup_field, NestedCalldataExecution,
            NestedCalldataFieldKey, NestedCalldataParentKey, NestedCalleeLocation,
        },
        params::DYNAMIC_KIND_BYTES,
        policy::TerminalKind,
    };

    if !matches!(ir.context_kind, ContextKind::Contract)
        || params.visibility != Visibility::Always
        || kind != TerminalKind::DynamicBytes
        || params.dynamic_kind != Some(DYNAMIC_KIND_BYTES)
        || params.nested_selector.is_some()
        || params.word_guard.is_some()
        || params.interpolated_intent.is_some()
        || field.path_off == 0
    {
        return Err(IrError::BadField);
    }
    let field_path = ir.path_bytes(field.path_off)?;
    let field_slot = calldata_field_slot(field_path).ok_or(IrError::BadField)?;
    let field_path: &[u8; 5] = field_path.try_into().map_err(|_| IrError::BadField)?;
    if field_slot >= format.static_head_words {
        return Err(IrError::BadField);
    }
    let callee_path = params.nested_callee.ok_or(IrError::BadField)?;
    match callee_location(callee_path).ok_or(IrError::BadField)? {
        NestedCalleeLocation::ContainerTo => {}
        NestedCalleeLocation::StaticWord(slot) if slot < format.static_head_words => {}
        NestedCalleeLocation::StaticWord(_) => return Err(IrError::BadField),
    }

    let enrollment = lookup_field(
        enrollments,
        NestedCalldataFieldKey {
            parent: NestedCalldataParentKey {
                descriptor_hash: &ir.descriptor_hash,
                chain_id: ir.chain_id,
                parent_contract: &ir.contract,
                parent_selector: &format.selector,
            },
            field_ordinal,
            field_path,
            callee_path,
        },
    )
    .map_err(|_| IrError::BadFormat)?
    .ok_or(IrError::BadFormat)?;
    if enrollment.execution != NestedCalldataExecution::CallZeroValue {
        return Err(IrError::BadFormat);
    }
    Ok(())
}

/// Independently reconcile an authenticated terminal kind with the structural
/// path shape available to the device.  The semantic kind itself is supplied
/// by schema v6; this belt prevents a dynamic/constant/container path from
/// contradicting that authenticated claim.
fn validate_terminal_path_shape(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    kind: crate::render::policy::TerminalKind,
    params: &crate::render::params::ParamSet<'_>,
    forbid_nested: bool,
) -> Result<(), IrError> {
    use crate::{
        abi::container_field,
        render::{params::DYNAMIC_KIND_STRING, policy::TerminalKind},
    };

    match kind {
        TerminalKind::ConstantText => {
            if field.path_off != 0 || params.const_value.is_none() {
                return Err(IrError::BadField);
            }
            return Ok(());
        }
        TerminalKind::NestedStruct => {
            if forbid_nested || field.path_off != 0 || params.nested_struct.is_none() {
                return Err(IrError::BadField);
            }
            return Ok(());
        }
        _ if field.path_off == 0 => return Err(IrError::BadField),
        _ => {}
    }

    let path = ir.path_bytes(field.path_off)?;
    let ends_dynamic = path.last().copied() == Some(PathOp::FollowOffset as u8);
    match kind {
        TerminalKind::DynamicString => {
            if !ends_dynamic || params.dynamic_kind != Some(DYNAMIC_KIND_STRING) {
                return Err(IrError::BadField);
            }
        }
        TerminalKind::DynamicBytes => {
            // No current formatter admits arbitrary dynamic bytes, but retain
            // the structural check so a future matrix extension cannot skip it.
            if !ends_dynamic
                || params.dynamic_kind != Some(crate::render::params::DYNAMIC_KIND_BYTES)
            {
                return Err(IrError::BadField);
            }
        }
        _ if ends_dynamic || params.dynamic_kind.is_some() => return Err(IrError::BadField),
        _ => {}
    }

    // Container fields have a firmware-owned type vocabulary, so validate the
    // exact kind without trusting dbgen's claim.
    if path.first().copied() == Some(PathOp::RootContainer as u8) {
        if path.len() != 4 || path[1] != PathOp::FieldIdx as u8 {
            return Err(IrError::BadField);
        }
        let idx = u16::from_be_bytes([path[2], path[3]]);
        let expected = match idx {
            container_field::TO | container_field::FROM => TerminalKind::Address,
            container_field::VALUE | container_field::CHAIN_ID | container_field::NONCE => {
                TerminalKind::Unsigned
            }
            _ => return Err(IrError::BadField),
        };
        if kind != expected
            || expected == TerminalKind::Unsigned && params.integer_width_bytes != Some(32)
        {
            return Err(IrError::BadField);
        }
    }
    Ok(())
}

fn is_uniswap_router02_packed_identity(ir: &Erc7730Ir<'_>, format: &FormatHeader<'_>) -> bool {
    matches!(ir.context_kind, ContextKind::Contract)
        && ir.chain_id == UNISWAP_ROUTER02_CHAIN_ID
        && ir.contract == UNISWAP_ROUTER02_MAINNET
        && matches!(
            format.selector,
            UNISWAP_V3_EXACT_INPUT_SELECTOR | UNISWAP_V3_EXACT_OUTPUT_SELECTOR
        )
}

fn router02_packed_member_path(path: &[u8], member: u16, dynamic: bool) -> bool {
    let expected_len = if dynamic { 9 } else { 8 };
    path.len() == expected_len
        && path[0] == PathOp::RootStructured as u8
        && path[1] == PathOp::FieldIdx as u8
        && path[2..4] == [0, 0]
        && path[4] == PathOp::FollowOffset as u8
        && path[5] == PathOp::FieldIdx as u8
        && path[6..8] == member.to_be_bytes()
        && (!dynamic || path[8] == PathOp::FollowOffset as u8)
}

fn is_router02_packed_scalar_path(path: &[u8]) -> bool {
    (1..=3).any(|member| router02_packed_member_path(path, member, false))
}

fn is_router02_packed_token_path(path: &[u8], member: u16) -> bool {
    if path.len() != 15
        || !router02_packed_member_path(&path[..9], 0, true)
        || path[9] != PathOp::ArraySlice as u8
        || path[12..14] != 20u16.to_be_bytes()
    {
        return false;
    }
    match member {
        2 => path[10..12] == 0u16.to_be_bytes() && path[14] == 0,
        3 => path[10..12] == 0u16.to_be_bytes() && path[14] == 1,
        _ => false,
    }
}

/// Deep device-side belt for the only active C2 format. A forged authenticated
/// IR cannot use the new opcode as a generic `bytes` renderer or reuse the
/// Router02 selector while changing the five reviewed operand roles.
fn validate_uniswap_v3_format(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    packed_fields: u8,
    packed_identity: bool,
) -> Result<(), IrError> {
    if packed_fields == 0 {
        return Ok(());
    }
    if packed_fields != 1
        || !packed_identity
        || format.static_head_words != 1
        || format.field_count != 5
        || format.nested_descent_count != 0
    {
        return Err(IrError::BadFormat);
    }

    let mut saw_value = false;
    let mut saw_amount_member_2 = false;
    let mut saw_amount_member_3 = false;
    let mut saw_recipient = false;
    let mut saw_route = false;
    let zero_word = [0u8; 32];
    let mut address_two_word = [0u8; 32];
    address_two_word[31] = 2;
    for field in format.fields() {
        let field = field?;
        let op = FormatOp::try_from(field.format_op)?;
        let params =
            crate::render::params::parse(ir, field.param_off).map_err(|_| IrError::BadPoolEntry)?;
        if params.visibility != Visibility::Always {
            return Err(IrError::BadField);
        }
        let path = ir.path_bytes(field.path_off)?;
        match op {
            FormatOp::Amount => {
                let value = crate::abi::container_field::VALUE.to_be_bytes();
                if saw_value
                    || field.label != b"Native value"
                    || path
                        != [
                            PathOp::RootContainer as u8,
                            PathOp::FieldIdx as u8,
                            value[0],
                            value[1],
                        ]
                    || !params.word_guard.is_some_and(|guard| {
                        guard.mode() == crate::render::params::WORD_GUARD_EQ
                            && guard.expected() == &zero_word
                    })
                {
                    return Err(IrError::BadField);
                }
                saw_value = true;
            }
            FormatOp::TokenAmount => {
                let member = if router02_packed_member_path(path, 2, false) {
                    2
                } else if router02_packed_member_path(path, 3, false) {
                    3
                } else {
                    return Err(IrError::BadField);
                };
                if !params
                    .token_path
                    .is_some_and(|token_path| is_router02_packed_token_path(token_path, member))
                {
                    return Err(IrError::BadField);
                }
                let (seen, expected_label, guard_required) = match (format.selector, member) {
                    (UNISWAP_V3_EXACT_INPUT_SELECTOR, 2) => {
                        (&mut saw_amount_member_2, b"Swap input".as_slice(), true)
                    }
                    (UNISWAP_V3_EXACT_INPUT_SELECTOR, 3) => (
                        &mut saw_amount_member_3,
                        b"Minimum to Receive".as_slice(),
                        false,
                    ),
                    (UNISWAP_V3_EXACT_OUTPUT_SELECTOR, 2) => (
                        &mut saw_amount_member_2,
                        b"Amount to Receive".as_slice(),
                        false,
                    ),
                    (UNISWAP_V3_EXACT_OUTPUT_SELECTOR, 3) => (
                        &mut saw_amount_member_3,
                        b"Max swap input".as_slice(),
                        false,
                    ),
                    _ => return Err(IrError::BadField),
                };
                if *seen || field.label != expected_label {
                    return Err(IrError::BadField);
                }
                match (guard_required, params.word_guard) {
                    (true, Some(guard))
                        if guard.mode() == crate::render::params::WORD_GUARD_NE
                            && guard.expected() == &zero_word => {}
                    (false, None) => {}
                    _ => return Err(IrError::BadField),
                }
                *seen = true;
            }
            FormatOp::AddressName => {
                if saw_recipient
                    || field.label != b"Beneficiary"
                    || !router02_packed_member_path(path, 1, false)
                    || params.sender_addresses
                        != Some(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..])
                    || !params.word_guard.is_some_and(|guard| {
                        guard.mode() == crate::render::params::WORD_GUARD_NE
                            && guard.expected() == &address_two_word
                    })
                {
                    return Err(IrError::BadField);
                }
                saw_recipient = true;
            }
            FormatOp::UniswapV3Path => {
                if saw_route
                    || field.label != b"Route"
                    || !router02_packed_member_path(path, 0, true)
                    || params.terminal_kind
                        != Some(crate::render::policy::TerminalKind::DynamicBytes)
                    || params.dynamic_kind != Some(crate::render::params::DYNAMIC_KIND_BYTES)
                    || params.word_guard.is_some()
                {
                    return Err(IrError::BadField);
                }
                saw_route = true;
            }
            _ => return Err(IrError::BadField),
        }
    }
    if !(saw_value && saw_amount_member_2 && saw_amount_member_3 && saw_recipient && saw_route) {
        return Err(IrError::BadFormat);
    }
    Ok(())
}

/// Validate the orthogonal exact-word predicate independently of formatter
/// policy. Guards are accepted only on paths that the corresponding renderer
/// evaluates before publishing trusted pages: static contract scalars or one
/// top-level EIP-712 encodeData word. The expected value is canonical for the
/// authenticated terminal type, preventing impossible-EQ and vacuous-NE
/// guards over dirty ABI encodings.
fn validate_word_guard(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    kind: crate::render::policy::TerminalKind,
    params: &crate::render::params::ParamSet<'_>,
    allow_packed_v3_c2: bool,
) -> Result<(), IrError> {
    use crate::render::policy::{integer_word_is_canonical, TerminalKind};

    let Some(guard) = params.word_guard else {
        return Ok(());
    };
    if params.visibility != Visibility::Always
        || !matches!(kind, TerminalKind::Unsigned | TerminalKind::Address)
        || field.path_off == 0
    {
        return Err(IrError::BadField);
    }

    let path = ir.path_bytes(field.path_off)?;
    match ir.context_kind {
        ContextKind::Contract => validate_word_guard_scalar_path(path, allow_packed_v3_c2)?,
        ContextKind::Eip712 => validate_eip712_word_guard_path(path)?,
    }
    if path.first().copied() == Some(PathOp::RootContainer as u8)
        && (kind != TerminalKind::Unsigned || params.integer_width_bytes != Some(32))
    {
        return Err(IrError::BadField);
    }
    let expected = guard.expected();
    match kind {
        TerminalKind::Address if expected[..12].iter().any(|&byte| byte != 0) => {
            Err(IrError::BadField)
        }
        TerminalKind::Unsigned => {
            let width = params.integer_width_bytes.ok_or(IrError::BadField)?;
            if integer_word_is_canonical(kind, width, expected) {
                Ok(())
            } else {
                Err(IrError::BadField)
            }
        }
        TerminalKind::Address => Ok(()),
        _ => Err(IrError::BadField),
    }
}

pub(crate) fn validate_eip712_word_guard_path(path: &[u8]) -> Result<(), IrError> {
    if path.len() == 4
        && path[0] == PathOp::RootStructured as u8
        && path[1] == PathOp::FieldIdx as u8
    {
        Ok(())
    } else {
        Err(IrError::BadField)
    }
}

fn validate_word_guard_scalar_path(path: &[u8], allow_packed_v3_c2: bool) -> Result<(), IrError> {
    match path
        .first()
        .copied()
        .and_then(|byte| PathOp::try_from(byte).ok())
    {
        Some(PathOp::RootStructured) => {
            if allow_packed_v3_c2 && is_router02_packed_scalar_path(path) {
                return Ok(());
            }
            let mut cursor = 1usize;
            let mut steps = 0usize;
            while cursor < path.len() {
                if path.get(cursor).copied() != Some(PathOp::FieldIdx as u8) {
                    return Err(IrError::BadField);
                }
                cursor = cursor.checked_add(3).ok_or(IrError::BadField)?;
                if cursor > path.len() {
                    return Err(IrError::BadField);
                }
                steps += 1;
            }
            if steps == 0 {
                return Err(IrError::BadField);
            }
            Ok(())
        }
        Some(PathOp::RootContainer)
            if path.len() == 4
                && path[1] == PathOp::FieldIdx as u8
                && u16::from_be_bytes([path[2], path[3]]) == crate::abi::container_field::VALUE =>
        {
            Ok(())
        }
        _ => Err(IrError::BadField),
    }
}

fn validate_pool_entry(pool: &[u8], off: u16) -> Result<(), IrError> {
    let off = off as usize;
    let len = *pool.get(off).ok_or(IrError::BadPoolEntry)? as usize;
    if len + 1 > MAX_POOL_ENTRY_LEN {
        return Err(IrError::OverCap);
    }
    pool.get(off + 1..off + 1 + len)
        .ok_or(IrError::BadPoolEntry)?;
    Ok(())
}

fn validate_path_program(prog: &[u8]) -> Result<(), IrError> {
    let Some(&root) = prog.first() else {
        return Err(IrError::BadField);
    };
    if !matches!(
        PathOp::try_from(root)?,
        PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata
    ) {
        return Err(IrError::BadField);
    }
    let mut p = 1usize;
    let mut steps = 0usize;
    while p < prog.len() {
        steps += 1;
        if steps > MAX_NESTING {
            return Err(IrError::OverCap);
        }
        let op = PathOp::try_from(prog[p])?;
        let width = match op {
            PathOp::FieldIdx | PathOp::ArrayIdx => 3,
            PathOp::ArraySlice => 6,
            PathOp::ArrayLast | PathOp::ArrayAll | PathOp::FollowOffset => 1,
            PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata => {
                return Err(IrError::BadField)
            }
        };
        p = p.checked_add(width).ok_or(IrError::BadField)?;
        if p > prog.len() {
            return Err(IrError::BadField);
        }
    }
    Ok(())
}

/// Interpolation v1 deliberately witnesses only a static structured scalar.
/// The compiler proves the terminal ABI type is unsigned; this device-side
/// belt independently excludes container/dynamic/array path bytecode.
fn validate_interpolated_scalar_path(prog: &[u8]) -> Result<(), IrError> {
    if prog.first().copied() != Some(PathOp::RootStructured as u8) {
        return Err(IrError::BadField);
    }
    let mut cursor = 1usize;
    let mut steps = 0usize;
    while cursor < prog.len() {
        if prog.get(cursor).copied() != Some(PathOp::FieldIdx as u8) {
            return Err(IrError::BadField);
        }
        cursor = cursor.checked_add(3).ok_or(IrError::BadField)?;
        if cursor > prog.len() {
            return Err(IrError::BadField);
        }
        steps += 1;
    }
    if steps == 0 {
        return Err(IrError::BadField);
    }
    Ok(())
}

/// Parsed view of one format-table entry. Borrows from the IR's
/// `formats` slice; cheap to copy.
///
/// Wire layout the host emitter writes
/// (`dbgen::erc7730::compile_one_format`):
///
/// ```text
///   selector             [u8; 4]
///   field_count          u8       (≤ MAX_FIELDS_PER_FORMAT)
///   intent_len           u8       (≤ 254, printable ASCII)
///   static_head_words    u16 BE   (ABI static head, in 32-byte words)
///   nested_descent_count u8       (introduced in v4 — E1 reconciliation pin)
///   string_preimage_count u8      (introduced in v6 — exact evidence pin)
///   intent               [u8; intent_len]
///   type_hash            [u8; 32] (EIP-712 context ONLY — see below)
///   field                [u8; ...]*  (field_count entries — see FieldEntry)
/// ```
///
/// `static_head_words` is the number of 32-byte words in the function's
/// ABI static head (for EIP-712, the typed-data member count). The
/// renderer truncates the body to this many words before walking fields,
/// so a path slot that lands beyond the static head (a malformed
/// descriptor reaching into the dynamic tail) is rejected instead of
/// silently rendered. Schema v2.
///
/// `type_hash` is present only for EIP-712-context descriptors (the
/// header's `context_kind == CTX_EIP712`); contract-context entries omit
/// it entirely so their bytes are unchanged. It is the FULL 32-byte
/// `keccak256(primaryType encodeType)` whose first 4 bytes are
/// [`selector`](Self::selector). The renderer binds the companion-supplied
/// `primary_type_hash` against all 32 bytes before rendering, closing the
/// 4-byte-prefix-only gap (audit M-5): selecting the display template by a
/// 4-byte truncation while the signature commits to the full hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatHeader<'a> {
    pub selector: [u8; 4],
    pub field_count: u8,
    /// ABI static head width in 32-byte words. The renderer truncates the
    /// calldata/typed-data body to this length before walking fields, so
    /// any path slot reaching past the static head is rejected. Schema v2.
    pub static_head_words: u16,
    /// Number of nested-EIP-712 struct descent points in this format (the
    /// count of `PARAM_NESTED_STRUCT` v0x03 anchors, recursively). Pinned by
    /// dbgen from `struct_defs` — INDEPENDENT of the render traversal — so the
    /// E1 reconciliation (`records_consumed == nested_descent_count`) is a real
    /// regression tripwire, not a tautology: a future edit that makes descent
    /// conditional drops the runtime consume-count below this pin → decline.
    /// `0` for every contract-context format and every non-nested EIP-712
    /// format. Introduced in schema v4 and retained by schema v6.
    pub nested_descent_count: u8,
    /// Number of exact EIP-712 string preimages consumed by this format. Deep
    /// validation requires exactly this many top-level markers, with ordinals
    /// `0..count` in field traversal order. Contract formats must carry zero.
    /// Introduced in schema v6.
    pub string_preimage_count: u8,
    /// Trimmed printable ASCII intent string ("Sign", "Wrap", …).
    pub intent: &'a [u8],
    /// Full 32-byte EIP-712 primary-type hash (`keccak256(encodeType)`).
    /// All-zero for contract-context formats, which don't carry it on the
    /// wire. `selector == type_hash[..4]` for EIP-712 entries.
    pub type_hash: [u8; 32],
    /// Raw bytes of the field-entry array. Parse via
    /// [`FieldEntry::next_from`].
    pub fields_buf: &'a [u8],
}

impl<'a> FormatHeader<'a> {
    /// Iterate the format's field entries.
    pub fn fields(&self) -> FieldIter<'a> {
        FieldIter {
            buf: self.fields_buf,
            cursor: 0,
            remaining: self.field_count,
        }
    }
}

/// One field of a format. The path / param offsets index into
/// `Erc7730Ir::pool`; live renderers read the program bytes via
/// [`Erc7730Ir::path_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldEntry<'a> {
    /// Formatter opcode — feed to `FormatOp::try_from`.
    pub format_op: u8,
    /// Trimmed printable ASCII label.
    pub label: &'a [u8],
    /// Offset of the path program inside `ir.pool` (length-prefixed
    /// `[u8 len][opcodes]`). `0` means "no path".
    pub path_off: u16,
    /// Offset of the TLV parameter blob inside `ir.pool` (length-
    /// prefixed). `0` means "no params".
    pub param_off: u16,
}

impl<'a> FieldEntry<'a> {
    /// Pop one entry from `buf` starting at `cursor`. Returns the
    /// entry and the byte position immediately after it.
    fn next_from(buf: &'a [u8], cursor: usize) -> Result<(Self, usize), IrError> {
        let mut p = cursor;
        if p + 2 > buf.len() {
            return Err(IrError::BadFormat);
        }
        let format_op = buf[p];
        let label_len = buf[p + 1] as usize;
        p += 2;
        if p + label_len > buf.len() {
            return Err(IrError::BadFormat);
        }
        let label = &buf[p..p + label_len];
        if !label.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Err(IrError::BadAscii);
        }
        p += label_len;
        if p + 4 > buf.len() {
            return Err(IrError::BadFormat);
        }
        let path_off = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let param_off = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
        p += 4;
        Ok((
            FieldEntry {
                format_op,
                label,
                path_off,
                param_off,
            },
            p,
        ))
    }
}

/// Iterator over `Erc7730Ir::format_iter()`. Yields `Result` items so
/// a malformed entry halts iteration with a typed error rather than
/// dropping silently.
pub struct FormatIter<'a> {
    buf: &'a [u8],
    cursor: usize,
    remaining: u8,
    /// EIP-712-context descriptors carry a 32-byte `type_hash` after each
    /// format's intent string; contract-context ones don't. Threaded from
    /// the IR header's `context_kind` so the same parser handles both.
    is_eip712: bool,
}

impl<'a> Iterator for FormatIter<'a> {
    type Item = Result<FormatHeader<'a>, IrError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let mut p = self.cursor;
        // Header: 4 (selector) + 1 (field_count) + 1 (intent_len)
        //         + 2 (static_head_words) + 1 (nested_descent_count)
        //         + 1 (string_preimage_count).
        if p + 10 > self.buf.len() {
            return Some(Err(IrError::BadFormat));
        }
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&self.buf[p..p + 4]);
        let field_count = self.buf[p + 4];
        if (field_count as usize) > MAX_FIELDS_PER_FORMAT {
            return Some(Err(IrError::OverCap));
        }
        let intent_len = self.buf[p + 5] as usize;
        let static_head_words = u16::from_be_bytes([self.buf[p + 6], self.buf[p + 7]]);
        let nested_descent_count = self.buf[p + 8];
        let string_preimage_count = self.buf[p + 9];
        p += 10;
        if p + intent_len > self.buf.len() {
            return Some(Err(IrError::BadFormat));
        }
        let intent = &self.buf[p..p + intent_len];
        if !intent.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Some(Err(IrError::BadAscii));
        }
        p += intent_len;
        // EIP-712 formats carry a full 32-byte primary-type hash after
        // the intent (contract formats don't). See `FormatHeader`.
        let type_hash = if self.is_eip712 {
            if p + 32 > self.buf.len() {
                return Some(Err(IrError::BadFormat));
            }
            let mut th = [0u8; 32];
            th.copy_from_slice(&self.buf[p..p + 32]);
            p += 32;
            th
        } else {
            [0u8; 32]
        };
        // Advance past every field entry to compute the start of the
        // next format. Each entry's length is variable (label_len),
        // so we have to parse field-by-field.
        let fields_start = p;
        for _ in 0..field_count {
            match FieldEntry::next_from(self.buf, p) {
                Ok((_, next)) => p = next,
                Err(e) => return Some(Err(e)),
            }
        }
        let fields_buf = &self.buf[fields_start..p];
        self.cursor = p;
        Some(Ok(FormatHeader {
            selector,
            field_count,
            static_head_words,
            nested_descent_count,
            string_preimage_count,
            intent,
            type_hash,
            fields_buf,
        }))
    }
}

/// Iterator yielded by `FormatHeader::fields`.
pub struct FieldIter<'a> {
    buf: &'a [u8],
    cursor: usize,
    remaining: u8,
}

impl<'a> FieldIter<'a> {
    /// Iterate `count` [`FieldEntry`] records from an arbitrary buffer. The
    /// sub-field records inside a `PARAM_NESTED_STRUCT` v0x03 block share the
    /// FieldEntry wire format (`format_op | label_len | label | path_off |
    /// param_off`), so the nested-struct renderer reuses this exact parser —
    /// including its label-ASCII + bounds checks — instead of re-implementing
    /// it. Introduced in schema v4 and retained by schema v6.
    pub fn from_buf(buf: &'a [u8], count: u8) -> Self {
        FieldIter {
            buf,
            cursor: 0,
            remaining: count,
        }
    }

    /// Bytes consumed so far. Used by the nested renderer to assert the
    /// sub-field records consume EXACTLY the block (no trailing bytes) — the
    /// per-block half of the E4-3 total-consumption invariant.
    pub fn cursor(&self) -> usize {
        self.cursor
    }
}

impl<'a> Iterator for FieldIter<'a> {
    type Item = Result<FieldEntry<'a>, IrError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        match FieldEntry::next_from(self.buf, self.cursor) {
            Ok((entry, next)) => {
                self.cursor = next;
                Some(Ok(entry))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Trim canonical trailing NUL padding and verify the surviving bytes are
/// clean printable ASCII. Used for `owner` and `contract_name`.
fn trim_nul(buf: &[u8]) -> Result<&[u8], IrError> {
    let end = buf.iter().position(|&b| b == 0).ok_or(IrError::BadAscii)?;
    // These are fixed-width, NUL-terminated fields. Accepting non-zero bytes
    // after the first terminator would authenticate multiple wire encodings
    // for the same displayed string and hide attacker-controlled bytes from
    // the UI. Require one canonical zero-filled suffix, including the NUL.
    if buf[end..].iter().any(|&b| b != 0) {
        return Err(IrError::BadAscii);
    }
    let body = &buf[..end];
    if !is_clean_ascii(body) {
        return Err(IrError::BadAscii);
    }
    Ok(body)
}

/// Match `pqsigner-tx::erc20::bundle::is_clean_ascii` byte-for-byte —
/// reject control bytes and bytes outside printable ASCII.
fn is_clean_ascii(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..0x7f).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid header: contract context, mainnet,
    /// USDC mainnet, both string slots empty, empty pool, zero formats.
    fn minimal_header() -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        // contract bytes [10..30] left zero — fine, just for shape
        // testing. descriptor_hash zero, domain_separator zero. Pool +
        // formats both empty.
        buf[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        // pool_len = 0, formats_len = 0 already.
        // Formats section needs at least one byte for the count.
        buf.push(0u8);
        let formats_len = 1u16;
        let formats_off = HEADER_LEN as u16;
        buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
        buf[132..134].copy_from_slice(&formats_len.to_be_bytes());
        buf
    }

    fn build_ir_with_pool(pool: std::vec::Vec<u8>) -> std::vec::Vec<u8> {
        let pool_len = pool.len();
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        let metadata_off = HEADER_LEN as u16;
        let formats_off = (HEADER_LEN + pool_len) as u16;
        buf[126..128].copy_from_slice(&metadata_off.to_be_bytes());
        buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
        buf[130..132].copy_from_slice(&(pool_len as u16).to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&pool);
        buf.push(0u8); // format count
        buf
    }

    fn build_ir(pool: &[u8], formats: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        buf[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&((HEADER_LEN + pool.len()) as u16).to_be_bytes());
        buf[130..132].copy_from_slice(&(pool.len() as u16).to_be_bytes());
        buf[132..134].copy_from_slice(&(formats.len() as u16).to_be_bytes());
        buf.extend_from_slice(pool);
        buf.extend_from_slice(formats);
        buf
    }

    fn one_field_format(selector: [u8; 4], format_op: u8) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&selector);
        out.push(1); // field count
        out.push(0); // intent len
        out.extend_from_slice(&1u16.to_be_bytes()); // static head words
        out.push(0); // nested descent count
        out.push(0); // string preimage count
        out.push(format_op);
        out.push(1); // label len
        out.push(b'X');
        out.extend_from_slice(&1u16.to_be_bytes()); // path offset
        out.extend_from_slice(&6u16.to_be_bytes()); // terminal-kind params
        out
    }

    /// Root-structured FieldIdx(0) plus the schema-v5 mandatory authenticated
    /// unsigned terminal-kind and full-width integer metadata at offset 6.
    fn scalar_pool() -> std::vec::Vec<u8> {
        std::vec![
            0,
            4,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            6,
            crate::render::params::PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::Unsigned as u8,
            crate::render::params::PARAM_INTEGER_WIDTH,
            1,
            32,
        ]
    }

    fn exact_empty_bytes_pool(
        slot: u16,
        include_marker: bool,
        extra_tlvs: &[u8],
    ) -> (std::vec::Vec<u8>, u16) {
        use crate::render::params::{
            DYNAMIC_KIND_BYTES, PARAM_DYNAMIC_KIND, PARAM_EXACT_EMPTY_BYTES, PARAM_TERMINAL_KIND,
        };

        let mut pool = std::vec![
            0,
            5,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            (slot >> 8) as u8,
            slot as u8,
            PathOp::FollowOffset as u8,
        ];
        let param_off = pool.len() as u16;
        let mut body = std::vec![
            PARAM_DYNAMIC_KIND,
            1,
            DYNAMIC_KIND_BYTES,
            PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::DynamicBytes as u8,
        ];
        if include_marker {
            body.extend_from_slice(&[PARAM_EXACT_EMPTY_BYTES, 0]);
        }
        body.extend_from_slice(extra_tlvs);
        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);
        (pool, param_off)
    }

    fn exact_empty_field(label: &[u8], param_off: u16) -> std::vec::Vec<u8> {
        let mut field = std::vec![FormatOp::Raw as u8, label.len() as u8];
        field.extend_from_slice(label);
        field.extend_from_slice(&1u16.to_be_bytes());
        field.extend_from_slice(&param_off.to_be_bytes());
        field
    }

    fn exact_empty_format(
        selector: [u8; 4],
        head_words: u16,
        fields: &[std::vec::Vec<u8>],
    ) -> std::vec::Vec<u8> {
        let mut format = std::vec::Vec::new();
        format.extend_from_slice(&selector);
        format.push(fields.len() as u8);
        format.push(0);
        format.extend_from_slice(&head_words.to_be_bytes());
        format.push(0);
        format.push(0);
        for field in fields {
            format.extend_from_slice(field);
        }
        format
    }

    fn append_pool_entry(pool: &mut std::vec::Vec<u8>, payload: &[u8]) -> u16 {
        let offset = pool.len() as u16;
        pool.push(payload.len() as u8);
        pool.extend_from_slice(payload);
        offset
    }

    fn tail_topology_payload(
        records: &[(u16, crate::render::calldata_topology::TailKind)],
    ) -> std::vec::Vec<u8> {
        use crate::render::calldata_topology::TOPOLOGY_VERSION;

        let mut payload = std::vec![TOPOLOGY_VERSION, records.len() as u8];
        for &(slot, kind) in records {
            payload.extend_from_slice(&slot.to_be_bytes());
            payload.push(kind as u8);
        }
        payload
    }

    fn topology_tlv(
        records: &[(u16, crate::render::calldata_topology::TailKind)],
    ) -> std::vec::Vec<u8> {
        let payload = tail_topology_payload(records);
        let mut tlv = std::vec![
            crate::render::params::PARAM_DYNAMIC_TAIL_TOPOLOGY,
            payload.len() as u8,
        ];
        tlv.extend_from_slice(&payload);
        tlv
    }

    fn scalar_params(extra_tlvs: &[u8]) -> std::vec::Vec<u8> {
        let mut params = extra_tlvs.to_vec();
        params.extend_from_slice(&[
            crate::render::params::PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::Unsigned as u8,
            crate::render::params::PARAM_INTEGER_WIDTH,
            1,
            32,
        ]);
        params
    }

    fn encoded_field(
        op: FormatOp,
        label: &[u8],
        path_off: u16,
        param_off: u16,
    ) -> std::vec::Vec<u8> {
        let mut field = std::vec![op as u8, label.len() as u8];
        field.extend_from_slice(label);
        field.extend_from_slice(&path_off.to_be_bytes());
        field.extend_from_slice(&param_off.to_be_bytes());
        field
    }

    fn nested_calldata_ir(
        field_path: &[u8],
        callee_path: &[u8],
        extra_nested_params: &[u8],
        calldata_first: bool,
        add_second_dynamic_path: bool,
    ) -> std::vec::Vec<u8> {
        nested_calldata_ir_with_target_params(
            field_path,
            callee_path,
            extra_nested_params,
            calldata_first,
            add_second_dynamic_path,
            &[],
        )
    }

    fn nested_calldata_ir_with_target_params(
        field_path: &[u8],
        callee_path: &[u8],
        extra_nested_params: &[u8],
        calldata_first: bool,
        add_second_dynamic_path: bool,
        extra_target_params: &[u8],
    ) -> std::vec::Vec<u8> {
        use crate::render::{
            calldata_policy::{
                TEST_NESTED_CALLDATA_DESCRIPTOR_HASH, TEST_NESTED_CALLDATA_PARENT_CONTRACT,
                TEST_NESTED_CALLDATA_PARENT_SELECTOR,
            },
            params::{
                DYNAMIC_KIND_BYTES, DYNAMIC_KIND_STRING, PARAM_DYNAMIC_KIND, PARAM_NESTED_CALLEE,
                PARAM_TERMINAL_KIND,
            },
            policy::TerminalKind,
        };

        let mut pool = std::vec![0];
        let target_path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let mut target_params = extra_target_params.to_vec();
        target_params.extend_from_slice(&[PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8]);
        let target_param_off = append_pool_entry(&mut pool, &target_params);
        let nested_path_off = append_pool_entry(&mut pool, field_path);
        let mut nested_params = std::vec![
            PARAM_DYNAMIC_KIND,
            1,
            DYNAMIC_KIND_BYTES,
            PARAM_NESTED_CALLEE,
            callee_path.len() as u8,
        ];
        nested_params.extend_from_slice(callee_path);
        nested_params.extend_from_slice(extra_nested_params);
        nested_params.extend_from_slice(&[
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::DynamicBytes as u8,
        ]);
        let nested_param_off = append_pool_entry(&mut pool, &nested_params);

        let target = encoded_field(
            FormatOp::AddressName,
            b"Target",
            target_path_off,
            target_param_off,
        );
        let nested = encoded_field(
            FormatOp::Calldata,
            b"Call",
            nested_path_off,
            nested_param_off,
        );
        let mut fields = if calldata_first {
            std::vec![nested, target]
        } else {
            std::vec![target, nested]
        };
        if add_second_dynamic_path {
            let extra_param_off = append_pool_entry(
                &mut pool,
                &[
                    PARAM_DYNAMIC_KIND,
                    1,
                    DYNAMIC_KIND_STRING,
                    PARAM_TERMINAL_KIND,
                    1,
                    TerminalKind::DynamicString as u8,
                ],
            );
            fields.push(encoded_field(
                FormatOp::Raw,
                b"Again",
                nested_path_off,
                extra_param_off,
            ));
        }

        let mut format = std::vec::Vec::new();
        format.extend_from_slice(&TEST_NESTED_CALLDATA_PARENT_SELECTOR);
        format.push(fields.len() as u8);
        format.push(0); // intent len
        format.extend_from_slice(&2u16.to_be_bytes());
        format.push(0); // nested descent count
        format.push(0); // string preimage count
        for field in fields {
            format.extend_from_slice(&field);
        }
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        let mut bytes = build_ir(&pool, &formats);
        bytes[2..10].copy_from_slice(&31_337u64.to_be_bytes());
        bytes[10..30].copy_from_slice(&TEST_NESTED_CALLDATA_PARENT_CONTRACT);
        bytes[30..62].copy_from_slice(&TEST_NESTED_CALLDATA_DESCRIPTOR_HASH);
        bytes
    }

    fn eip712_string_field(
        pool: &mut std::vec::Vec<u8>,
        path: &[u8],
        ordinal: Option<u8>,
        kind: crate::render::policy::TerminalKind,
        op: FormatOp,
        extra_tlvs: &[u8],
    ) -> std::vec::Vec<u8> {
        let path_off = pool.len() as u16;
        pool.push(path.len() as u8);
        pool.extend_from_slice(path);

        let param_off = pool.len() as u16;
        let mut body = std::vec![crate::render::params::PARAM_TERMINAL_KIND, 1, kind as u8,];
        if let Some(ordinal) = ordinal {
            body.extend_from_slice(&[
                crate::render::params::PARAM_EIP712_STRING_PREIMAGE,
                1,
                ordinal,
            ]);
        }
        body.extend_from_slice(extra_tlvs);
        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);

        let mut field = std::vec![op as u8, 6];
        field.extend_from_slice(b"String");
        field.extend_from_slice(&path_off.to_be_bytes());
        field.extend_from_slice(&param_off.to_be_bytes());
        field
    }

    fn eip712_format(
        selector: [u8; 4],
        head_words: u16,
        string_preimage_count: u8,
        fields: &[std::vec::Vec<u8>],
    ) -> std::vec::Vec<u8> {
        let mut format = std::vec::Vec::new();
        format.extend_from_slice(&selector);
        format.push(fields.len() as u8);
        format.push(0); // intent len
        format.extend_from_slice(&head_words.to_be_bytes());
        format.push(0); // nested descent count
        format.push(string_preimage_count);
        let mut type_hash = [0u8; 32];
        type_hash[..4].copy_from_slice(&selector);
        format.extend_from_slice(&type_hash);
        for field in fields {
            format.extend_from_slice(field);
        }
        format
    }

    fn build_eip712_ir(pool: &[u8], format: &[u8]) -> std::vec::Vec<u8> {
        let mut formats = std::vec![1];
        formats.extend_from_slice(format);
        let mut bytes = build_ir(pool, &formats);
        bytes[1] = CTX_EIP712;
        bytes
    }

    fn guarded_scalar_pool(
        path: [u8; 4],
        kind: crate::render::policy::TerminalKind,
        width: Option<u8>,
        sender: Option<[u8; 20]>,
        visibility: Option<Visibility>,
        mode: u8,
        expected: [u8; 32],
    ) -> std::vec::Vec<u8> {
        use crate::render::params::{
            PARAM_INTEGER_WIDTH, PARAM_SENDER_ADDRESS, PARAM_TERMINAL_KIND, PARAM_VISIBILITY,
            PARAM_WORD_GUARD,
        };

        let mut body = std::vec![PARAM_WORD_GUARD, 33, mode];
        body.extend_from_slice(&expected);
        if let Some(sentinel) = sender {
            body.extend_from_slice(&[PARAM_SENDER_ADDRESS, 20]);
            body.extend_from_slice(&sentinel);
        }
        if let Some(visibility) = visibility {
            body.extend_from_slice(&[PARAM_VISIBILITY, 1, visibility as u8]);
        }
        body.extend_from_slice(&[PARAM_TERMINAL_KIND, 1, kind as u8]);
        if let Some(width) = width {
            body.extend_from_slice(&[PARAM_INTEGER_WIDTH, 1, width]);
        }

        let mut pool = std::vec![0, path.len() as u8];
        pool.extend_from_slice(&path);
        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);
        pool
    }

    fn unsigned_container_pool(field: u16, width_bytes: u8) -> std::vec::Vec<u8> {
        std::vec![
            0,
            4,
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (field >> 8) as u8,
            field as u8,
            6,
            crate::render::params::PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::Unsigned as u8,
            crate::render::params::PARAM_INTEGER_WIDTH,
            1,
            width_bytes,
        ]
    }

    fn interpolation_pool_with_program(
        program: &[u8],
        extra_param_tlvs: &[u8],
    ) -> std::vec::Vec<u8> {
        let mut pool = std::vec![
            0,
            4,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
        ];
        let body_len = 2 + program.len() + extra_param_tlvs.len() + 6;
        pool.push(body_len as u8);
        pool.push(crate::render::params::PARAM_INTERPOLATED_INTENT);
        pool.push(program.len() as u8);
        pool.extend_from_slice(program);
        pool.extend_from_slice(extra_param_tlvs);
        pool.extend_from_slice(&[
            crate::render::params::PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::Unsigned as u8,
            crate::render::params::PARAM_INTEGER_WIDTH,
            1,
            32,
        ]);
        pool
    }

    fn interpolation_pool(field_ordinal: u8, extra_param_tlvs: &[u8]) -> std::vec::Vec<u8> {
        interpolation_pool_with_program(&[1, 1, 0, field_ordinal, 0], extra_param_tlvs)
    }

    fn interpolated_field_format(
        selector: [u8; 4],
        format_op: u8,
        field_ordinal: u8,
        extra_param_tlvs: &[u8],
    ) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let pool = interpolation_pool(field_ordinal, extra_param_tlvs);
        let mut format = one_field_format(selector, format_op);
        let param_off = 6u16;
        let param_pos = format.len() - 2;
        format[param_pos..].copy_from_slice(&param_off.to_be_bytes());
        (pool, format)
    }

    #[test]
    fn deep_validation_rejects_format_count_over_cap() {
        let bytes = build_ir(&[], &[(MAX_FORMATS as u8) + 1]);
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::OverCap));
    }

    #[test]
    fn deep_validation_accepts_static_word_guards_and_address_sender_substitution() {
        use crate::render::{params::WORD_GUARD_NE, policy::TerminalKind};

        let structured = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
        let mut forbidden_recipient = [0u8; 32];
        forbidden_recipient[31] = 2;
        let pool = guarded_scalar_pool(
            structured,
            TerminalKind::Address,
            None,
            Some({
                let mut sentinel = [0u8; 20];
                sentinel[19] = 1;
                sentinel
            }),
            None,
            WORD_GUARD_NE,
            forbidden_recipient,
        );
        let mut formats = std::vec![1];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::AddressName as u8));
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());

        let container_value = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (crate::abi::container_field::VALUE >> 8) as u8,
            crate::abi::container_field::VALUE as u8,
        ];
        let pool = guarded_scalar_pool(
            container_value,
            TerminalKind::Unsigned,
            Some(32),
            None,
            None,
            crate::render::params::WORD_GUARD_EQ,
            [0u8; 32],
        );
        let mut formats = std::vec![1];
        formats.extend_from_slice(&one_field_format([5, 6, 7, 8], FormatOp::Amount as u8));
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());
    }

    #[test]
    fn deep_validation_accepts_only_top_level_eip712_word_guards() {
        use crate::render::{
            params::{PARAM_INTEGER_WIDTH, PARAM_WORD_GUARD, WORD_GUARD_EQ},
            policy::TerminalKind,
        };

        let mut guard_tlvs = std::vec![PARAM_WORD_GUARD, 33, WORD_GUARD_EQ];
        let mut expected = [0u8; 32];
        expected[31] = 1;
        guard_tlvs.extend_from_slice(&expected);
        guard_tlvs.extend_from_slice(&[PARAM_INTEGER_WIDTH, 1, 32]);

        let mut pool = std::vec![0];
        let field = eip712_string_field(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
            None,
            TerminalKind::Unsigned,
            FormatOp::Raw,
            &guard_tlvs,
        );
        let format = eip712_format([1, 2, 3, 4], 1, 0, &[field]);
        assert!(Erc7730Ir::parse(&build_eip712_ir(&pool, &format)).is_ok());

        let mut nested_pool = std::vec![0];
        let nested = eip712_string_field(
            &mut nested_pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::FieldIdx as u8,
                0,
                0,
            ],
            None,
            TerminalKind::Unsigned,
            FormatOp::Raw,
            &guard_tlvs,
        );
        let nested_format = eip712_format([1, 2, 3, 4], 1, 0, &[nested]);
        assert_eq!(
            Erc7730Ir::parse(&build_eip712_ir(&nested_pool, &nested_format)),
            Err(IrError::BadField)
        );
    }

    #[test]
    fn deep_validation_accepts_one_direct_always_visible_exact_empty_callback() {
        let (pool, param_off) = exact_empty_bytes_pool(0, true, &[]);
        let format = exact_empty_format(
            [1, 2, 3, 4],
            1,
            &[exact_empty_field(b"Callback", param_off)],
        );
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());
    }

    #[test]
    fn nested_calldata_deep_validation_requires_exact_test_only_enrollment() {
        use crate::render::calldata_policy::{
            PRODUCTION_NESTED_CALLDATA_ENROLLMENTS, TEST_NESTED_CALLDATA_CALLEE_PATH,
            TEST_NESTED_CALLDATA_ENROLLMENTS, TEST_NESTED_CALLDATA_FIELD_PATH,
        };

        let bytes = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        );
        assert!(Erc7730Ir::parse_with_nested_calldata_enrollments(
            &bytes,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .is_ok());
        assert_eq!(
            Erc7730Ir::parse_with_nested_calldata_enrollments(
                &bytes,
                PRODUCTION_NESTED_CALLDATA_ENROLLMENTS,
            ),
            Err(IrError::BadFormat)
        );

        let duplicates = [
            TEST_NESTED_CALLDATA_ENROLLMENTS[0],
            TEST_NESTED_CALLDATA_ENROLLMENTS[0],
        ];
        assert_eq!(
            Erc7730Ir::parse_with_nested_calldata_enrollments(&bytes, &duplicates),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn nested_calldata_allows_other_dynamic_paths_only_with_authenticated_topology() {
        use crate::render::{
            calldata_policy::{
                TEST_NESTED_CALLDATA_CALLEE_PATH, TEST_NESTED_CALLDATA_ENROLLMENTS,
                TEST_NESTED_CALLDATA_FIELD_PATH,
            },
            calldata_topology::TailKind,
        };

        let legacy = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            true,
        );
        assert_eq!(
            Erc7730Ir::parse_with_nested_calldata_enrollments(
                &legacy,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            ),
            Err(IrError::BadFormat)
        );

        let records = [(0, TailKind::Blob), (1, TailKind::Blob)];
        let marked = nested_calldata_ir_with_target_params(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            true,
            &topology_tlv(&records),
        );
        assert!(Erc7730Ir::parse_with_nested_calldata_enrollments(
            &marked,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .is_ok());
    }

    #[test]
    fn nested_calldata_deep_validation_rejects_near_semantics() {
        use crate::render::{
            calldata_policy::{
                TEST_NESTED_CALLDATA_CALLEE_PATH, TEST_NESTED_CALLDATA_ENROLLMENTS,
                TEST_NESTED_CALLDATA_FIELD_PATH,
            },
            params::{PARAM_NESTED_SELECTOR, PARAM_VISIBILITY},
        };

        let rejects = |bytes: &[u8]| {
            assert!(Erc7730Ir::parse_with_nested_calldata_enrollments(
                bytes,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            )
            .is_err());
        };

        let mut wrong_descriptor = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        );
        wrong_descriptor[30] ^= 1;
        rejects(&wrong_descriptor);

        let mut wrong_chain = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        );
        wrong_chain[9] ^= 1;
        rejects(&wrong_chain);

        let mut wrong_contract = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        );
        wrong_contract[10] ^= 1;
        rejects(&wrong_contract);

        let mut wrong_selector = nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        );
        let formats_off = u16::from_be_bytes([wrong_selector[128], wrong_selector[129]]) as usize;
        wrong_selector[formats_off + 1] ^= 1;
        rejects(&wrong_selector);

        let mut wrong_field_path = TEST_NESTED_CALLDATA_FIELD_PATH;
        wrong_field_path[3] = 0;
        rejects(&nested_calldata_ir(
            &wrong_field_path,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            false,
        ));

        let mut wrong_callee = TEST_NESTED_CALLDATA_CALLEE_PATH;
        wrong_callee[3] = 1;
        rejects(&nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &wrong_callee,
            &[],
            false,
            false,
        ));

        rejects(&nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[PARAM_VISIBILITY, 1, Visibility::Optional as u8],
            false,
            false,
        ));
        rejects(&nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[PARAM_NESTED_SELECTOR, 4, 1, 2, 3, 4],
            false,
            false,
        ));
        rejects(&nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            true,
            false,
        ));
        rejects(&nested_calldata_ir(
            &TEST_NESTED_CALLDATA_FIELD_PATH,
            &TEST_NESTED_CALLDATA_CALLEE_PATH,
            &[],
            false,
            true,
        ));
    }

    #[test]
    fn deep_validation_accepts_one_contract_tail_topology_on_field_zero() {
        use crate::render::calldata_topology::TailKind;

        let records = [(0, TailKind::Blob), (1, TailKind::StaticWordArray)];
        let mut pool = std::vec![0];
        let path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let param_off = append_pool_entry(&mut pool, &scalar_params(&topology_tlv(&records)));
        let field = encoded_field(FormatOp::Amount, b"Value", path_off, param_off);
        let format = exact_empty_format([1, 2, 3, 4], 2, &[field]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());

        // Absence retains the established static-format interpretation.
        let mut legacy_formats = std::vec![1];
        legacy_formats.extend_from_slice(&one_field_format([5, 6, 7, 8], FormatOp::Amount as u8));
        assert!(Erc7730Ir::parse(&build_ir(&scalar_pool(), &legacy_formats)).is_ok());
    }

    #[test]
    fn deep_validation_rejects_tail_topology_outside_field_zero_or_static_head() {
        use crate::render::calldata_topology::TailKind;

        let records = [(0, TailKind::Blob), (1, TailKind::StaticWordArray)];
        let mut pool = std::vec![0];
        let path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let plain_params = append_pool_entry(&mut pool, &scalar_params(&[]));
        let topology_params = append_pool_entry(&mut pool, &scalar_params(&topology_tlv(&records)));
        let fields = [
            encoded_field(FormatOp::Amount, b"First", path_off, plain_params),
            encoded_field(FormatOp::Amount, b"Second", path_off, topology_params),
        ];
        let format = exact_empty_format([1, 2, 3, 4], 2, &fields);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );

        let duplicate_fields = [
            encoded_field(FormatOp::Amount, b"First", path_off, topology_params),
            encoded_field(FormatOp::Amount, b"Second", path_off, topology_params),
        ];
        let duplicate = exact_empty_format([1, 2, 3, 4], 2, &duplicate_fields);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&duplicate);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );

        let outside = [(0, TailKind::Blob), (2, TailKind::StaticWordArray)];
        let mut pool = std::vec![0];
        let path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let param_off = append_pool_entry(&mut pool, &scalar_params(&topology_tlv(&outside)));
        let field = encoded_field(FormatOp::Amount, b"Value", path_off, param_off);
        let format = exact_empty_format([1, 2, 3, 4], 2, &[field]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn deep_validation_rejects_tail_topology_in_eip712_context() {
        use crate::render::calldata_topology::TailKind;

        let records = [(0, TailKind::Blob), (1, TailKind::StaticWordArray)];
        let mut pool = std::vec![0];
        let path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let param_off = append_pool_entry(&mut pool, &scalar_params(&topology_tlv(&records)));
        let field = encoded_field(FormatOp::Amount, b"Value", path_off, param_off);
        let format = eip712_format([1, 2, 3, 4], 2, 0, &[field]);
        assert_eq!(
            Erc7730Ir::parse(&build_eip712_ir(&pool, &format)),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn deep_validation_rejects_tail_topology_in_nested_eip712_subfield() {
        use crate::render::{
            calldata_topology::TailKind,
            nested::NESTED_V3,
            params::{PARAM_NESTED_STRUCT, PARAM_TERMINAL_KIND},
            policy::TerminalKind,
        };

        let records = [(0, TailKind::Blob), (1, TailKind::StaticWordArray)];
        let mut pool = std::vec![0];
        let nested_path_off = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let nested_param_off =
            append_pool_entry(&mut pool, &scalar_params(&topology_tlv(&records)));
        let nested_field = encoded_field(
            FormatOp::Amount,
            b"Nested value",
            nested_path_off,
            nested_param_off,
        );

        let mut nested_payload = std::vec![NESTED_V3, 0, 0]; // parent word position
        nested_payload.extend_from_slice(&[0u8; 32]); // nested type hash
        nested_payload.extend_from_slice(&1u16.to_be_bytes()); // one local word
        nested_payload.push(0); // scalar struct
        nested_payload.push(0); // no address-typed local words
        nested_payload.push(1); // one sub-field
        nested_payload.extend_from_slice(&nested_field);

        let mut anchor_params = std::vec![PARAM_NESTED_STRUCT, nested_payload.len() as u8];
        anchor_params.extend_from_slice(&nested_payload);
        anchor_params.extend_from_slice(&[
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::NestedStruct as u8,
        ]);
        let anchor_param_off = append_pool_entry(&mut pool, &anchor_params);
        let anchor = encoded_field(FormatOp::Raw, b"Nested", 0, anchor_param_off);
        let mut format = eip712_format([1, 2, 3, 4], 1, 0, &[anchor]);
        format[8] = 1; // one authenticated nested descent
        assert_eq!(
            Erc7730Ir::parse(&build_eip712_ir(&pool, &format)),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn deep_validation_rejects_unmarked_or_misbound_exact_empty_bytes() {
        use crate::render::params::{PARAM_VISIBILITY, PARAM_WORD_GUARD};

        let cases: &[(u16, bool, &[u8], &[u8], u16)] = &[
            (0, false, &[], b"Callback", 1),
            (
                0,
                true,
                &[PARAM_VISIBILITY, 1, Visibility::Never as u8],
                b"Callback",
                1,
            ),
            (0, true, &[], b"Data", 1),
            (1, true, &[], b"Callback", 1),
            // A dynamic field cannot also carry the static-word predicate.
            (0, true, &[PARAM_WORD_GUARD, 0], b"Callback", 1),
        ];
        for &(slot, marker, extra, label, head_words) in cases {
            let (pool, param_off) = exact_empty_bytes_pool(slot, marker, extra);
            let format = exact_empty_format(
                [1, 2, 3, 4],
                head_words,
                &[exact_empty_field(label, param_off)],
            );
            let mut formats = std::vec![1];
            formats.extend_from_slice(&format);
            assert!(
                Erc7730Ir::parse(&build_ir(&pool, &formats)).is_err(),
                "accepted invalid exact-empty case slot={slot} marker={marker} label={label:?}"
            );
        }
    }

    #[test]
    fn deep_validation_rejects_exact_empty_bytes_outside_contract_or_more_than_once() {
        let selector = [1, 2, 3, 4];
        let (pool, param_off) = exact_empty_bytes_pool(0, true, &[]);
        let field = exact_empty_field(b"Callback", param_off);

        let duplicated = exact_empty_format(selector, 1, &[field.clone(), field.clone()]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&duplicated);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );

        let contract_format = exact_empty_format(selector, 1, &[field]);
        let mut eip712_format = contract_format[..10].to_vec();
        let mut type_hash = [0u8; 32];
        type_hash[..4].copy_from_slice(&selector);
        eip712_format.extend_from_slice(&type_hash);
        eip712_format.extend_from_slice(&contract_format[10..]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&eip712_format);
        let mut bytes = build_ir(&pool, &formats);
        bytes[1] = CTX_EIP712;
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadField));
    }

    #[test]
    fn deep_validation_accepts_ordered_top_level_eip712_string_preimages() {
        use crate::render::policy::TerminalKind;

        let mut pool = std::vec![0];
        let first = eip712_string_field(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
            Some(0),
            TerminalKind::Eip712StringHashWord,
            FormatOp::Raw,
            &[],
        );
        let second = eip712_string_field(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 2],
            Some(1),
            TerminalKind::Eip712StringHashWord,
            FormatOp::Raw,
            &[],
        );
        let format = eip712_format([1, 2, 3, 4], 3, 2, &[first, second]);
        let bytes = build_eip712_ir(&pool, &format);
        let parsed = Erc7730Ir::parse(&bytes).unwrap();
        let header = parsed.format_iter().next().unwrap().unwrap();
        assert_eq!(header.string_preimage_count, 2);
    }

    #[test]
    fn deep_validation_rejects_string_preimage_count_and_ordinal_drift() {
        use crate::render::policy::TerminalKind;

        for (header_count, ordinals) in
            [(0, &[0][..]), (1, &[][..]), (2, &[1, 0][..]), (2, &[0][..])]
        {
            let mut pool = std::vec![0];
            let mut fields = std::vec::Vec::new();
            for (slot, ordinal) in ordinals.iter().copied().enumerate() {
                fields.push(eip712_string_field(
                    &mut pool,
                    &[
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        0,
                        slot as u8,
                    ],
                    Some(ordinal),
                    TerminalKind::Eip712StringHashWord,
                    FormatOp::Raw,
                    &[],
                ));
            }
            let format = eip712_format([1, 2, 3, 4], 2, header_count, &fields);
            assert!(
                Erc7730Ir::parse(&build_eip712_ir(&pool, &format)).is_err(),
                "accepted count={header_count}, ordinals={ordinals:?}"
            );
        }

        let over_cap = eip712_format(
            [1, 2, 3, 4],
            1,
            (MAX_EIP712_STRING_PREIMAGES + 1) as u8,
            &[],
        );
        assert_eq!(
            Erc7730Ir::parse(&build_eip712_ir(&[], &over_cap)),
            Err(IrError::OverCap)
        );

        let mut contract_format = one_field_format([1, 2, 3, 4], FormatOp::Raw as u8);
        contract_format[9] = 1;
        let mut formats = std::vec![1];
        formats.extend_from_slice(&contract_format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&scalar_pool(), &formats)),
            Err(IrError::BadFormat)
        );

        let mut pool = std::vec![0];
        let field = eip712_string_field(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
            Some(0),
            TerminalKind::Eip712StringHashWord,
            FormatOp::Raw,
            &[],
        );
        let mut contract_marker = std::vec![1, 2, 3, 4, 1, 0, 0, 1, 0, 1];
        contract_marker.extend_from_slice(&field);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&contract_marker);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadField)
        );
    }

    #[test]
    fn deep_validation_rejects_noncanonical_eip712_string_marker_topologies() {
        use crate::render::{
            params::{DYNAMIC_KIND_STRING, PARAM_DYNAMIC_KIND, PARAM_VISIBILITY},
            policy::TerminalKind,
        };

        struct Case<'a> {
            path: &'a [u8],
            ordinal: Option<u8>,
            kind: TerminalKind,
            op: FormatOp,
            extra_tlvs: &'a [u8],
            head_words: u16,
        }

        let direct = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
        let followed = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FollowOffset as u8,
        ];
        let container = [PathOp::RootContainer as u8, PathOp::FieldIdx as u8, 0, 0];
        let hidden = [PARAM_VISIBILITY, 1, Visibility::Never as u8];
        let dynamic = [PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING];
        let cases = [
            Case {
                path: &direct,
                ordinal: None,
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(1),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Amount,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(0),
                kind: TerminalKind::Address,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &hidden,
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &dynamic,
                head_words: 1,
            },
            Case {
                path: &followed,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &container,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 1,
            },
            Case {
                path: &direct,
                ordinal: Some(0),
                kind: TerminalKind::Eip712StringHashWord,
                op: FormatOp::Raw,
                extra_tlvs: &[],
                head_words: 0,
            },
        ];

        for case in cases {
            let mut pool = std::vec![0];
            let field = eip712_string_field(
                &mut pool,
                case.path,
                case.ordinal,
                case.kind,
                case.op,
                case.extra_tlvs,
            );
            let format = eip712_format([1, 2, 3, 4], case.head_words, 1, &[field]);
            assert!(Erc7730Ir::parse(&build_eip712_ir(&pool, &format)).is_err());
        }
    }

    #[test]
    fn deep_validation_rejects_hidden_dirty_or_misapplied_word_semantics() {
        use crate::render::{params::WORD_GUARD_EQ, policy::TerminalKind};

        let structured = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
        let mut formats = std::vec![1];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Amount as u8));

        let hidden = guarded_scalar_pool(
            structured,
            TerminalKind::Unsigned,
            Some(32),
            None,
            Some(Visibility::Never),
            WORD_GUARD_EQ,
            [0u8; 32],
        );
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&hidden, &formats)),
            Err(IrError::BadField)
        );

        let mut dirty_uint24 = [0u8; 32];
        dirty_uint24[0] = 1;
        let dirty = guarded_scalar_pool(
            structured,
            TerminalKind::Unsigned,
            Some(3),
            None,
            None,
            WORD_GUARD_EQ,
            dirty_uint24,
        );
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&dirty, &formats)),
            Err(IrError::BadField)
        );

        let address = guarded_scalar_pool(
            structured,
            TerminalKind::Address,
            None,
            Some([1u8; 20]),
            None,
            WORD_GUARD_EQ,
            [0u8; 32],
        );
        let mut wrong_formatter = std::vec![1];
        wrong_formatter.extend_from_slice(&one_field_format(
            [9, 8, 7, 6],
            FormatOp::InteroperableAddressName as u8,
        ));
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&address, &wrong_formatter)),
            Err(IrError::BadField)
        );

        let container_to = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (crate::abi::container_field::TO >> 8) as u8,
            crate::abi::container_field::TO as u8,
        ];
        let disallowed_container = guarded_scalar_pool(
            container_to,
            TerminalKind::Address,
            None,
            None,
            None,
            WORD_GUARD_EQ,
            [0u8; 32],
        );
        let mut address_format = std::vec![1];
        address_format
            .extend_from_slice(&one_field_format([4, 3, 2, 1], FormatOp::AddressName as u8));
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&disallowed_container, &address_format)),
            Err(IrError::BadField)
        );
    }

    #[test]
    fn deep_validation_rejects_trailing_format_bytes() {
        let bytes = build_ir(&[], &[0, 0xAA]);
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadFormat));
    }

    #[test]
    fn deep_validation_rejects_duplicate_selectors() {
        let pool = scalar_pool();
        let mut formats = std::vec![2];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));
        let bytes = build_ir(&pool, &formats);
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadFormat));
    }

    #[test]
    fn deep_validation_checks_unselected_format_suffix() {
        let pool = scalar_pool();
        let mut formats = std::vec![2];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));
        formats.extend_from_slice(&one_field_format([5, 6, 7, 8], 0xFF));
        let bytes = build_ir(&pool, &formats);
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadField));
    }

    #[test]
    fn deep_validation_accepts_authenticated_narrow_structured_width() {
        let mut pool = scalar_pool();
        *pool.last_mut().unwrap() = 1;
        let mut formats = std::vec![1];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());
    }

    #[test]
    fn deep_validation_requires_full_width_for_unsigned_container_fields() {
        for field in [
            crate::abi::container_field::VALUE,
            crate::abi::container_field::CHAIN_ID,
            crate::abi::container_field::NONCE,
        ] {
            let mut formats = std::vec![1];
            formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));

            let narrow = unsigned_container_pool(field, 31);
            assert_eq!(
                Erc7730Ir::parse(&build_ir(&narrow, &formats)),
                Err(IrError::BadField),
                "accepted narrow width for container field {field}"
            );

            let full = unsigned_container_pool(field, 32);
            assert!(
                Erc7730Ir::parse(&build_ir(&full, &formats)).is_ok(),
                "rejected full width for container field {field}"
            );
        }
    }

    #[test]
    fn deep_validation_accepts_canonical_scalar_interpolation() {
        let (pool, format) =
            interpolated_field_format([1, 2, 3, 4], FormatOp::Amount as u8, 0, &[]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert!(Erc7730Ir::parse(&build_ir(&pool, &formats)).is_ok());
    }

    #[test]
    fn deep_validation_rejects_interpolated_erc20_approve_enrollment() {
        let (pool, format) =
            interpolated_field_format(ERC20_APPROVE_SELECTOR, FormatOp::Amount as u8, 0, &[]);
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn deep_validation_checks_interpolation_in_unselected_format_suffix() {
        let invalid_program = [1, 2, 0, 0, 0, 1, 0];
        let pool = interpolation_pool_with_program(&invalid_program, &[]);
        let mut bad_suffix = one_field_format([5, 6, 7, 8], FormatOp::Amount as u8);
        let param_pos = bad_suffix.len() - 2;
        bad_suffix[param_pos..].copy_from_slice(&6u16.to_be_bytes());

        let mut formats = std::vec![2];
        formats.extend_from_slice(&one_field_format([1, 2, 3, 4], FormatOp::Raw as u8));
        formats.extend_from_slice(&bad_suffix);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadPoolEntry)
        );
    }

    #[test]
    fn deep_validation_rejects_interpolation_oob_wrong_op_or_visibility() {
        let (oob_pool, oob_format) =
            interpolated_field_format([1, 2, 3, 4], FormatOp::Amount as u8, 1, &[]);
        let mut oob_formats = std::vec![1];
        oob_formats.extend_from_slice(&oob_format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&oob_pool, &oob_formats)),
            Err(IrError::BadFormat)
        );

        let (raw_pool, raw_format) =
            interpolated_field_format([1, 2, 3, 4], FormatOp::Raw as u8, 0, &[]);
        let mut raw_formats = std::vec![1];
        raw_formats.extend_from_slice(&raw_format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&raw_pool, &raw_formats)),
            Err(IrError::BadFormat)
        );

        let visibility_tlv = [
            crate::render::params::PARAM_VISIBILITY,
            1,
            Visibility::Optional as u8,
        ];
        let (optional_pool, optional_format) =
            interpolated_field_format([1, 2, 3, 4], FormatOp::Amount as u8, 0, &visibility_tlv);
        let mut optional_formats = std::vec![1];
        optional_formats.extend_from_slice(&optional_format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&optional_pool, &optional_formats)),
            Err(IrError::BadFormat)
        );
    }

    #[test]
    fn deep_validation_rejects_noncanonical_interpolation_placement() {
        let mut pool = interpolation_pool(1, &[]);
        let terminal_only_off = pool.len() as u16;
        pool.extend_from_slice(&[
            6,
            crate::render::params::PARAM_TERMINAL_KIND,
            1,
            crate::render::policy::TerminalKind::Unsigned as u8,
            crate::render::params::PARAM_INTEGER_WIDTH,
            1,
            32,
        ]);
        let mut format = std::vec::Vec::new();
        format.extend_from_slice(&[1, 2, 3, 4]);
        format.push(2); // field count
        format.push(0); // intent len
        format.extend_from_slice(&2u16.to_be_bytes());
        format.push(0); // nested descent count
        format.push(0); // string preimage count
        for param_off in [terminal_only_off, 6u16] {
            format.push(FormatOp::Amount as u8);
            format.push(1);
            format.push(b'X');
            format.extend_from_slice(&1u16.to_be_bytes());
            format.extend_from_slice(&param_off.to_be_bytes());
        }
        let mut formats = std::vec![1];
        formats.extend_from_slice(&format);
        assert_eq!(
            Erc7730Ir::parse(&build_ir(&pool, &formats)),
            Err(IrError::BadFormat)
        );
    }

    // `path_bytes` (review 5.4 — moved here from the retired legacy walker).
    #[test]
    fn path_bytes_zero_off_is_empty() {
        let ir_bytes = build_ir_with_pool(std::vec![]);
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert_eq!(ir.path_bytes(0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn path_bytes_reads_prefix() {
        // Pool: a 1-byte filler at offset 0 (so `path_off == 0` stays the
        // "no path" sentinel) and a 3-opcode program at offset 1:
        // `[len=3 | 0x10 0x20 0x00]` for `#.field0` — length byte at offset 1,
        // opcodes at 2..5.
        let pool = std::vec![0xFFu8, 3, 0x10, 0x20, 0x00];
        let ir_bytes = build_ir_with_pool(pool);
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert_eq!(ir.path_bytes(1).unwrap(), &[0x10u8, 0x20, 0x00]);
    }

    #[test]
    fn parse_minimal_header() {
        let bytes = minimal_header();
        let ir = Erc7730Ir::parse(&bytes).expect("minimal header should parse");
        assert_eq!(ir.schema_ver, SCHEMA_VER);
        assert_eq!(ir.context_kind, ContextKind::Contract);
        assert_eq!(ir.chain_id, 1);
        assert!(ir.owner.is_empty());
        assert!(ir.contract_name.is_empty());
        assert!(ir.pool.is_empty());
        assert_eq!(ir.formats.len(), 1);
        assert_eq!(ir.format_count().unwrap(), 0);
    }

    #[test]
    fn reject_too_short() {
        let bytes = std::vec![0u8; HEADER_LEN - 1];
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::TooShort));
    }

    #[test]
    fn reject_too_large() {
        let bytes = std::vec![0u8; MAX_IR_LEN + 1];
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::TooLarge));
    }

    #[test]
    fn reject_unknown_schema() {
        let mut bytes = minimal_header();
        bytes[0] = 0xFF;
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::SchemaVersion));
    }

    #[test]
    fn prior_schemas_are_rejected_after_string_preimage_migration() {
        let mut buf = minimal_header();
        for old_schema in [0x03, 0x04, 0x05] {
            buf[0] = old_schema;
            assert_eq!(Erc7730Ir::parse(&buf), Err(IrError::SchemaVersion));
        }
    }

    #[test]
    fn reject_unknown_context() {
        let mut bytes = minimal_header();
        bytes[1] = 0xFF;
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadContextKind));
    }

    #[test]
    fn reject_contract_ctx_with_domain_sep() {
        let mut bytes = minimal_header();
        bytes[62] = 0xAA;
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadLayout));
    }

    #[test]
    fn reject_non_ascii_owner() {
        let mut bytes = minimal_header();
        bytes[94] = 0x00; // first byte will be trimmed; smuggle below
        bytes[95] = 0x80; // non-ASCII but trimming above means
                          // truncation happens at byte 94 → this is
                          // also trimmed away. So push something
                          // before the NUL instead:
        bytes[94] = 0x80;
        bytes[95] = 0x00;
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadAscii));
    }

    #[test]
    fn accept_clean_owner() {
        let mut bytes = minimal_header();
        let label = b"Tether";
        bytes[94..94 + label.len()].copy_from_slice(label);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(ir.owner, label);
    }

    #[test]
    fn reject_nonzero_bytes_after_ascii_terminator() {
        let mut buf = minimal_header();
        buf[94..99].copy_from_slice(b"owner");
        buf[100] = b'X';
        assert_eq!(Erc7730Ir::parse(&buf), Err(IrError::BadAscii));
    }

    #[test]
    fn reject_unterminated_fixed_ascii_field() {
        let mut buf = minimal_header();
        buf[94..94 + OWNER_FIELD_LEN].fill(b'A');
        assert_eq!(Erc7730Ir::parse(&buf), Err(IrError::BadAscii));
    }

    #[test]
    fn reject_pool_offset_mismatch() {
        let mut bytes = minimal_header();
        // Push metadata_off off the end of the header → invalid.
        bytes[126..128].copy_from_slice(&((HEADER_LEN + 1) as u16).to_be_bytes());
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadLayout));
    }

    #[test]
    fn reject_formats_section_overrun() {
        let mut bytes = minimal_header();
        // Claim the formats section is 10 bytes longer than the blob.
        let claimed = (1u16 + 10).to_be_bytes();
        bytes[132..134].copy_from_slice(&claimed);
        assert_eq!(Erc7730Ir::parse(&bytes), Err(IrError::BadLayout));
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Panic / overflow / slice-OOB-freedom for the ERC-7730 clear-signing IR
    /// header parser over arbitrary (companion-supplied descriptor) bytes. The
    /// non-trivial part Kani discharges: the symbolic `metadata_off` / `pool_len`
    /// / `formats_off` / `formats_len` offsets (read from header bytes) combined
    /// with the layout checks (`metadata_off == HEADER_LEN`, `formats_off ==
    /// metadata_off + pool_len`, `formats_off + formats_len == bytes.len()`) must
    /// guarantee the final `&bytes[metadata_off..metadata_off+pool_len]` and
    /// `&bytes[formats_off..formats_off+formats_len]` slices are in-bounds — no
    /// hostile descriptor can panic the parser. `Ir::parse` is loop-free; the
    /// format/field iteration happens lazily in later methods.
    ///
    /// Scope: host-reachable pure-logic parser (no_std); bounded to N bytes for
    /// CBMC tractability — the (symbolic u16) offset arithmetic and every
    /// layout-check branch are exercised within this bound.
    #[kani::proof]
    #[kani::unwind(64)]
    fn erc7730_ir_parse_panic_free() {
        const N: usize = HEADER_LEN + 6; // header + room for a small pool/formats
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = Erc7730Ir::parse(&buf[..len]);
    }
}
