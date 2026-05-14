//! Binary IR for compiled ERC-7730 descriptors.
//!
//! The host pipeline (`dbgen::erc7730`) takes the registry JSON, runs
//! it through `erc7730 lint` equivalent + JCS canonicalisation, checks
//! the 8176 attestation policy, and emits one of these IR blobs per
//! qualifying descriptor. The blobs are then Merkle-tree-hashed into
//! `ERC7730_DESCRIPTORS_ROOT`, pinned in `secure/src/db_roots.rs`.
//!
//! The on-device walker reads the IR with zero copies. All offsets are
//! into the IR's own metadata pool; no string parsing at sign time.
//!
//! ## Header (134 B fixed)
//!
//! ```text
//!   off  size  field
//!    0    1   schema_ver         (0x01)
//!    1    1   context_kind       (CTX_CONTRACT | CTX_EIP712)
//!    2    8   chain_id (u64 BE)  (for EIP-712: domain.chainId)
//!   10   20   contract           (for EIP-712: domain.verifyingContract)
//!   30   32   descriptor_hash    (sha256 of JCS-canonicalised source
//!                                 JSON — same as the ERC-8176 hash,
//!                                 included for cross-device sanity)
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
//! - 16 formats per descriptor
//! - 24 fields per format
//! - 8 levels of nested calldata recursion
//! - 256 B per individual pool entry
//!
//! Parsing is strict — any unknown opcode, unaligned offset, or
//! pool-out-of-range index returns `IrError::Malformed`.

use core::convert::TryFrom;

pub const SCHEMA_VER: u8 = 0x01;
pub const HEADER_LEN: usize = 134;

pub const CTX_CONTRACT: u8 = 0x01;
pub const CTX_EIP712: u8 = 0x02;

pub const MAX_IR_LEN: usize = 4096;
pub const MAX_FORMATS: usize = 16;
pub const MAX_FIELDS_PER_FORMAT: usize = 24;
pub const MAX_NESTING: usize = 8;
pub const MAX_POOL_ENTRY_LEN: usize = 256;

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
    /// `[idx]` — array index (4 B BE).
    ArrayIdx = 0x21,
    /// `[start:end]` — slice (4 B BE start, 4 B BE end).
    ArraySlice = 0x22,
    /// `[-1]` — last element of an array.
    ArrayLast = 0x23,
    /// `[]` — whole array iteration.
    ArrayAll = 0x24,
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
    /// Parse the fixed header + locate the pool and formats sections
    /// without doing deep validation of either. Deep validation runs
    /// lazily in the walker as each format is rendered, so that the
    /// per-format cost is paid only when the format is actually picked.
    ///
    /// Reject blobs that:
    /// * are shorter than `HEADER_LEN`
    /// * are larger than `MAX_IR_LEN`
    /// * carry an unknown `schema_ver`
    /// * carry an unknown `context_kind`
    /// * declare pool/formats offsets that overlap or extend past EOF
    /// * carry non-printable bytes in the `owner` / `contract_name`
    ///   slots (anti-spoof: a hostile descriptor must not sneak
    ///   homoglyphs onto the trusted OLED)
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IrError> {
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
        let contract_name =
            trim_nul(&bytes[110..110 + CONTRACT_NAME_FIELD_LEN])?;

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

        Ok(Erc7730Ir {
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
        })
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
        }
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
}

/// Parsed view of one format-table entry. Borrows from the IR's
/// `formats` slice; cheap to copy.
///
/// Wire layout the host emitter writes
/// (`dbgen::erc7730::compile_one_format`):
///
/// ```text
///   selector       [u8; 4]
///   field_count    u8       (≤ MAX_FIELDS_PER_FORMAT)
///   intent_len     u8       (≤ 254, printable ASCII)
///   intent         [u8; intent_len]
///   field          [u8; ...]*  (field_count entries — see FieldEntry)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatHeader<'a> {
    pub selector: [u8; 4],
    pub field_count: u8,
    /// Trimmed printable ASCII intent string ("Sign", "Wrap", …).
    pub intent: &'a [u8],
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
/// `Erc7730Ir::pool`; the walker reads the program bytes via
/// `walker::path_bytes`.
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
}

impl<'a> Iterator for FormatIter<'a> {
    type Item = Result<FormatHeader<'a>, IrError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let mut p = self.cursor;
        // Header: 4 (selector) + 1 (field_count) + 1 (intent_len).
        if p + 6 > self.buf.len() {
            return Some(Err(IrError::BadFormat));
        }
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&self.buf[p..p + 4]);
        let field_count = self.buf[p + 4];
        if (field_count as usize) > MAX_FIELDS_PER_FORMAT {
            return Some(Err(IrError::OverCap));
        }
        let intent_len = self.buf[p + 5] as usize;
        p += 6;
        if p + intent_len > self.buf.len() {
            return Some(Err(IrError::BadFormat));
        }
        let intent = &self.buf[p..p + intent_len];
        if !intent.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            return Some(Err(IrError::BadAscii));
        }
        p += intent_len;
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
            intent,
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

/// Trim trailing NUL padding and verify the surviving bytes are clean
/// printable ASCII. Used for `owner` and `contract_name`.
fn trim_nul(buf: &[u8]) -> Result<&[u8], IrError> {
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(buf.len());
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
