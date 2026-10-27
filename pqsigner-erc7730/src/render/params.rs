//! TLV parameter parser for the ERC-7730 IR's per-field parameter blob.
//!
//! `FieldEntry::param_off` is a `u16` offset into `Erc7730Ir::pool`.
//! When non-zero, the byte at that offset is a single-byte length
//! prefix, followed by `len` bytes of TLV entries:
//!
//! ```text
//!   [u8 blob_len]              <- pool[param_off]
//!   [u8 kind][u8 payload_len][payload]*   <- pool[param_off + 1 ..]
//! ```
//!
//! Tag space (host-emitter constants, mirrored byte-for-byte from
//! `dbgen::erc7730::PARAM_*`):
//!
//! | Tag  | Meaning              | Payload shape                              |
//! |------|----------------------|--------------------------------------------|
//! | 0x30 | `token_path`         | path-bytecode program (≤255 B)             |
//! | 0x31 | `token`              | 20 B address                               |
//! | 0x32 | `threshold`          | 32 B BE u256                               |
//! | 0x33 | `message`            | ASCII (≤254 B)                             |
//! | 0x34 | `addr_types`         | 1 B bitset                                 |
//! | 0x35 | `addr_sources`       | 1 B bitset                                 |
//! | 0x36 | `date_encoding`      | 1 B (0=timestamp, 1=blockheight)           |
//! | 0x37 | `enum_ref`           | 2 B BE pool offset of enum row             |
//! | 0x38 | `decimals`           | 1 B u8                                     |
//! | 0x39 | `base`               | ASCII unit-suffix (≤254 B)                 |
//! | 0x3A | `prefix`             | 1 B u8                                     |
//! | 0x3B | `suffix`             | ASCII (≤254 B)                             |
//! | 0x3C | `nested_selector`    | 4 B function selector                      |
//! | 0x3D | `nested_callee`      | raw compiled `calleePath` program           |
//! | 0x3E | `fallback_label`     | ASCII (≤254 B)                             |
//! | 0x3F | `visibility`         | 1 B (Visibility byte value), optionally    |
//! |      |                      | followed by a Phase 5 value-list sub-TLV.  |
//! | 0x42 | `native_currency`    | 1–2 concatenated 20 B sentinel addresses  |
//! | 0x43 | `dynamic_kind`       | 1 B (`1=string`, `2=bytes`)                |
//! | 0x44 | `nft_collection`     | 20 B collection contract                   |
//! | 0x45 | `nft_collection_path`| exact compiled `@.to` container path       |
//! | 0x46 | `interpolated_intent`| v1 literal/field-ordinal bytecode (format) |
//! | 0x47 | `terminal_kind`      | 1 B [`TerminalKind`] (required)            |
//! | 0x48 | `integer_width`      | 1 B width in bytes, `1..=32` (integers)    |
//! | 0x49 | `sender_address`     | 1–2 unique concatenated 20 B sentinels     |
//! | 0x4A | `word_guard`         | mode (0=EQ, 1=NE) + exact 32 B word        |
//! | 0x4B | `exact_empty_bytes`  | empty (requires sole canonical empty tail) |
//! | 0x4C | `eip712_string_preimage` | 1 B evidence-stream ordinal          |
//! | 0x4D | `dynamic_tail_topology` | v1, 2–4 `(head_slot, kind)` records    |
//!
//! Wire-stable.
//!
//! Unknown tags are rejected — a hostile descriptor that smuggles an
//! unknown tag must NOT silently render: it might describe semantics
//! the renderer can't honour.

use crate::{
    abi::container_field,
    ir::{Erc7730Ir, PathOp, Visibility},
};

use super::{
    calldata_topology::TailTopology,
    policy::{ParamMask, TerminalKind},
    RenderErr,
};

// Re-export the tag constants so the formatter dispatcher (Step 3) and
// other intra-module consumers don't have to keep them in sync by
// hand. Wire-stable.
pub const PARAM_TOKEN_PATH: u8 = 0x30;
pub const PARAM_TOKEN: u8 = 0x31;
pub const PARAM_THRESHOLD: u8 = 0x32;
pub const PARAM_MESSAGE: u8 = 0x33;
pub const PARAM_ADDR_TYPES: u8 = 0x34;
pub const PARAM_ADDR_SOURCES: u8 = 0x35;
pub const PARAM_DATE_ENCODING: u8 = 0x36;
pub const PARAM_ENUM_REF: u8 = 0x37;
pub const PARAM_DECIMALS: u8 = 0x38;
pub const PARAM_BASE: u8 = 0x39;
pub const PARAM_PREFIX: u8 = 0x3A;
pub const PARAM_SUFFIX: u8 = 0x3B;
pub const PARAM_NESTED_SELECTOR: u8 = 0x3C;
pub const PARAM_NESTED_CALLEE: u8 = 0x3D;
pub const PARAM_FALLBACK_LABEL: u8 = 0x3E;
pub const PARAM_VISIBILITY: u8 = 0x3F;
/// Constant annotation string for a path-less field (`{value,label,format}`
/// with no path). The renderer shows the literal descriptor-pinned string.
pub const PARAM_CONST_VALUE: u8 = 0x40;
/// Format-level flag (emitted by `dbgen` on an EIP-712 format's first field)
/// marking that the primary type carries a nested struct member — a single
/// opaque `hashStruct` word the renderer cannot expand. When set, the
/// renderer rejects the WHOLE format, so a nested member (and any `address`
/// inside it) is never partially clear-signed or painted as a garbage word.
/// The secure dispatcher hard-refuses that verified/known tuple rather than
/// downgrading it (`VULN-erc7730-eip712-nested-struct-address-hide`, on-device
/// belt behind the build-time visibility gate).
pub const PARAM_NESTED_STRUCT: u8 = 0x41;
/// A `tokenAmount`'s `nativeCurrencyAddress` sentinel list. The legacy scalar
/// form remains byte-identical at 20 B; the registry's array form is two
/// descriptor-order 20 B addresses concatenated into the same authenticated
/// TLV. When the field's resolved token address equals any member, the amount
/// is rendered as the chain's native currency instead of an ERC-20 lookup.
pub const PARAM_NATIVE_CURRENCY: u8 = 0x42;
pub const NATIVE_CURRENCY_ADDRESS_LEN: usize = 20;
/// Current registry-complete bound: every pinned array contains exactly the
/// `0xEeee…` and zero-address sentinels. Larger lists fail closed until their
/// need and resource impact are reviewed explicitly.
pub const MAX_NATIVE_CURRENCY_ADDRESSES: usize = 2;
/// Compiler-authenticated ABI kind for a dynamic leaf. The path bytecode only
/// says "follow this offset"; without this tag the device cannot distinguish a
/// human string from arbitrary bytes. Missing/unknown kinds therefore decline.
pub const PARAM_DYNAMIC_KIND: u8 = 0x43;
/// Exact collection address carried by `nftName.params.collection`.
pub const PARAM_NFT_COLLECTION: u8 = 0x44;
/// Compiled collection-address path carried by
/// `nftName.params.collectionPath`.
pub const PARAM_NFT_COLLECTION_PATH: u8 = 0x45;
/// The only collection-path bytecode accepted by the current device slice:
/// `RootContainer / FieldIdx / @.to`. Keeping the exact four bytes here makes
/// the parser and the renderer's fault-containment belt share one policy.
pub const NFT_COLLECTION_TO_PATH: [u8; 4] = [
    PathOp::RootContainer as u8,
    PathOp::FieldIdx as u8,
    (container_field::TO >> 8) as u8,
    container_field::TO as u8,
];
/// Format-level `interpolatedIntent` program, parked exactly once on the
/// format's first field. The compiler resolves source paths to emitted field
/// ordinals, so the device never parses JSON paths or braces while signing.
pub const PARAM_INTERPOLATED_INTENT: u8 = 0x46;
/// Mandatory authenticated semantic kind of the field terminal.
/// This closes the static-word ambiguity where the path alone cannot tell an
/// address from a uint, bool, signed integer, or fixed bytes.
pub const PARAM_TERMINAL_KIND: u8 = 0x47;
/// Schema-v5 authenticated ABI width for an unsigned or signed integer
/// terminal, expressed in bytes.  The parser requires exactly one byte in
/// `1..=32`, requires the tag for integer terminal kinds, and forbids it for
/// every other terminal kind.
pub const PARAM_INTEGER_WIDTH: u8 = 0x48;
/// Descriptor-authenticated `addressName.params.senderAddress` sentinels.
/// An exact calldata-address match is substituted with the independently
/// derived UserOperation sender. The local bound keeps parsing and matching
/// fixed-capacity; a larger standard list fails closed.
pub const PARAM_SENDER_ADDRESS: u8 = 0x49;
pub const SENDER_ADDRESS_LEN: usize = 20;
pub const MAX_SENDER_ADDRESSES: usize = 2;
/// Field-local, format-wide-enforced scalar precondition. The renderer checks
/// every enrolled guard before publishing the intent banner.
pub const PARAM_WORD_GUARD: u8 = 0x4A;
pub const WORD_GUARD_PAYLOAD_LEN: usize = 33;
pub const WORD_GUARD_EQ: u8 = 0;
pub const WORD_GUARD_NE: u8 = 1;
/// Authenticated assertion that a `raw` dynamic-`bytes` field is the sole
/// canonical ABI tail and must contain exactly zero data bytes. The parameter
/// is a zero-payload marker: any payload is non-canonical and rejected.
pub const PARAM_EXACT_EMPTY_BYTES: u8 = 0x4B;
/// Schema-v6 marker selecting one exact string-preimage record from the
/// companion's descriptor-selected evidence stream. The payload is the
/// zero-based record ordinal; the enclosing format validator enforces the
/// canonical traversal sequence and the EIP-712-only static-word topology.
pub const PARAM_EIP712_STRING_PREIMAGE: u8 = 0x4C;
/// Format-level authenticated topology for two to four top-level dynamic ABI
/// objects. The versioned payload is parsed here; deep IR validation pins the
/// marker to field zero of a contract format and checks every head slot against
/// that format's authenticated static head.
pub const PARAM_DYNAMIC_TAIL_TOPOLOGY: u8 = 0x4D;
pub const DYNAMIC_KIND_STRING: u8 = 0x01;
pub const DYNAMIC_KIND_BYTES: u8 = 0x02;

/// First constrained interpolation-program wire shape. This root-pinned TLV
/// extension was introduced in IR schema v4 and is retained unchanged in v6;
/// the program carries its own version so future grammars cannot be
/// mixed-interpreted.
pub const INTERPOLATED_INTENT_VERSION: u8 = 0x01;
/// Wire-parser storage bound. The current executable subset below accepts
/// exactly one substitution and rejects every other count before walking the
/// payload; retaining the three-slot bound keeps renderer storage bounded.
pub const MAX_INTERPOLATED_SUBSTITUTIONS: usize = 3;
/// The OLED intent area is exactly two 16-cell rows. Interpolated output must
/// fit completely; unlike a static descriptor intent it never earns a `~`
/// truncation marker.
pub const MAX_INTERPOLATED_INTENT_LEN: usize = 32;

/// Validated view of one format-level interpolation program.
///
/// Payload grammar (all literal bytes printable ASCII):
///
/// ```text
/// version=1 | substitution_count
///   (literal_len | literal | field_ordinal) * substitution_count
/// final_literal_len | final_literal
/// ```
///
/// Version 1's executable subset has exactly one field ordinal and an empty
/// final literal. Bounds against the enclosing format's actual field count and
/// formatter/visibility policy are checked by `Erc7730Ir::validate_formats`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterpolatedIntentProgram<'a> {
    payload: &'a [u8],
    substitution_count: u8,
}

/// Canonically parsed exact-word predicate. The expected word remains borrowed
/// from the Merkle-authenticated IR pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordGuard<'a> {
    mode: u8,
    expected: &'a [u8; 32],
}

impl<'a> WordGuard<'a> {
    #[must_use]
    pub const fn mode(self) -> u8 {
        self.mode
    }

    #[must_use]
    pub const fn expected(self) -> &'a [u8; 32] {
        self.expected
    }

    #[must_use]
    pub fn accepts(self, actual: &[u8; 32]) -> bool {
        match self.mode {
            WORD_GUARD_EQ => actual == self.expected,
            WORD_GUARD_NE => actual != self.expected,
            _ => false,
        }
    }
}

impl<'a> InterpolatedIntentProgram<'a> {
    /// Parse and canonically validate a program independent of its enclosing
    /// format. This is called by the deep IR validator for every format,
    /// including unselected suffixes.
    pub fn parse(payload: &'a [u8]) -> Result<Self, RenderErr> {
        if payload.len() < 3 || payload[0] != INTERPOLATED_INTENT_VERSION {
            return Err(RenderErr::Reject("7730 bad interpolated intent"));
        }
        let substitution_count = payload[1] as usize;
        // Keep the authority-bearing cardinality check directly before the
        // payload walk. Besides being the single owner of this rule, the
        // explicit equality lets bounded model checking constrain the loop to
        // one iteration instead of expanding a symbolic hostile count.
        if substitution_count != 1 {
            return Err(RenderErr::Reject("7730 bad interpolation count"));
        }

        let mut cursor = 2usize;
        let mut literal_total = 0usize;
        let mut ordinals = [0u8; MAX_INTERPOLATED_SUBSTITUTIONS];
        for slot in 0..substitution_count {
            let literal = take_interpolated_literal(payload, &mut cursor)?;
            literal_total = literal_total
                .checked_add(literal.len())
                .ok_or(RenderErr::Reject("7730 interpolation overflow"))?;
            let ordinal = *payload
                .get(cursor)
                .ok_or(RenderErr::Reject("7730 truncated interpolation"))?;
            cursor += 1;
            if ordinals[..slot].contains(&ordinal) {
                return Err(RenderErr::Reject("7730 duplicate interpolation field"));
            }
            ordinals[slot] = ordinal;
        }
        let final_literal = take_interpolated_literal(payload, &mut cursor)?;
        if !interpolated_intent_suffix_is_executable(final_literal) {
            return Err(RenderErr::Reject("7730 unsupported interpolation shape"));
        }
        literal_total = literal_total
            .checked_add(final_literal.len())
            .ok_or(RenderErr::Reject("7730 interpolation overflow"))?;
        let minimum_output = literal_total
            .checked_add(substitution_count)
            .ok_or(RenderErr::Reject("7730 interpolation overflow"))?;
        if cursor != payload.len() || minimum_output > MAX_INTERPOLATED_INTENT_LEN {
            return Err(RenderErr::Reject("7730 bad interpolation length"));
        }

        // Display padding must not become a second wire spelling for the same
        // visible title. Interior spaces remain allowed (`"Send " + value`).
        let first_literal = literal_at(payload, substitution_count as u8, 0)?;
        if first_literal.first() == Some(&b' ') || final_literal.last() == Some(&b' ') {
            return Err(RenderErr::Reject("7730 padded interpolated intent"));
        }

        Ok(Self {
            payload,
            substitution_count: substitution_count as u8,
        })
    }

    #[must_use]
    pub const fn substitution_count(self) -> u8 {
        self.substitution_count
    }

    /// Literal segment `0..=substitution_count`.
    pub fn literal(self, index: u8) -> Result<&'a [u8], RenderErr> {
        literal_at(self.payload, self.substitution_count, index)
    }

    /// Emitted field ordinal for substitution `0..substitution_count`.
    pub fn field_ordinal(self, index: u8) -> Result<u8, RenderErr> {
        if index >= self.substitution_count {
            return Err(RenderErr::Reject("7730 interpolation index"));
        }
        let mut cursor = 2usize;
        for slot in 0..self.substitution_count {
            let _ = take_interpolated_literal(self.payload, &mut cursor)?;
            let ordinal = *self
                .payload
                .get(cursor)
                .ok_or(RenderErr::Reject("7730 truncated interpolation"))?;
            cursor += 1;
            if slot == index {
                return Ok(ordinal);
            }
        }
        Err(RenderErr::Reject("7730 interpolation index"))
    }
}

/// The current derived title ends with its one rendered witness. Broadening
/// this suffix changes what a verified descriptor may place on the confirm
/// banner and therefore requires a fresh review boundary.
fn interpolated_intent_suffix_is_executable(final_literal: &[u8]) -> bool {
    final_literal.is_empty()
}

/// True only for the exact authenticated collection path implemented by this
/// release. The formatter calls this again after parsing so a corrupted or
/// fault-injected `ParamSet` cannot reach the generic path resolver.
pub(crate) fn nft_collection_path_is_current_slice(payload: &[u8]) -> bool {
    payload == NFT_COLLECTION_TO_PATH.as_slice()
}

fn take_interpolated_literal<'a>(
    payload: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], RenderErr> {
    let len = *payload
        .get(*cursor)
        .ok_or(RenderErr::Reject("7730 truncated interpolation"))? as usize;
    *cursor += 1;
    let end = cursor
        .checked_add(len)
        .ok_or(RenderErr::Reject("7730 interpolation overflow"))?;
    let literal = payload
        .get(*cursor..end)
        .ok_or(RenderErr::Reject("7730 truncated interpolation"))?;
    if literal
        .iter()
        .any(|&b| !(0x20..0x7f).contains(&b) || matches!(b, b'{' | b'}'))
    {
        return Err(RenderErr::Reject("7730 bad interpolation literal"));
    }
    *cursor = end;
    Ok(literal)
}

fn literal_at<'a>(
    payload: &'a [u8],
    substitution_count: u8,
    index: u8,
) -> Result<&'a [u8], RenderErr> {
    if index > substitution_count {
        return Err(RenderErr::Reject("7730 interpolation index"));
    }
    let mut cursor = 2usize;
    for slot in 0..=substitution_count {
        let literal = take_interpolated_literal(payload, &mut cursor)?;
        if slot == index {
            return Ok(literal);
        }
        // Every non-final literal is followed by one field ordinal.
        cursor = cursor
            .checked_add(1)
            .ok_or(RenderErr::Reject("7730 interpolation overflow"))?;
        if cursor > payload.len() {
            return Err(RenderErr::Reject("7730 truncated interpolation"));
        }
    }
    Err(RenderErr::Reject("7730 interpolation index"))
}

/// `dbgen::erc7730::DATE_ENC_TIMESTAMP` — unix-seconds u64.
pub const DATE_ENC_TIMESTAMP: u8 = 0x00;
/// `dbgen::erc7730::DATE_ENC_BLOCKHEIGHT` — render as decimal block id.
pub const DATE_ENC_BLOCKHEIGHT: u8 = 0x01;

/// Address-type bitset bits (matches `dbgen::erc7730::ADDR_TYPE_*`).
pub const ADDR_TYPE_WALLET: u8 = 0x01;
pub const ADDR_TYPE_EOA: u8 = 0x02;
pub const ADDR_TYPE_CONTRACT: u8 = 0x04;
pub const ADDR_TYPE_NFT_COLLECTION: u8 = 0x08;
pub const ADDR_TYPE_TOKEN: u8 = 0x10;
pub const ADDR_TYPE_COLLECTION: u8 = 0x20;
/// Every address is an EOA or a contract, so a `types` set holding both
/// admits any address (see [`ParamSet::admits_db_name`]).
const ADDR_TYPES_ANY_ADDRESS: u8 = ADDR_TYPE_EOA | ADDR_TYPE_CONTRACT;

/// Parsed view of one field's TLV blob. All slices borrow from
/// `ir.pool`; the struct itself is stack-only.
///
/// `Default` is hand-rolled because `pqsigner_erc7730::ir::Visibility`
/// does not implement `Default` (the host-side enum has no canonical
/// "zero" value at the type level — Phase 4 chooses `Always` here, which
/// matches the on-wire default of "no VISIBILITY TLV present").
#[allow(dead_code)] // most fields are read by Step 3's formatter dispatch
pub struct ParamSet<'a> {
    pub token_path: Option<&'a [u8]>,
    pub token: Option<&'a [u8; 20]>,
    pub threshold: Option<&'a [u8; 32]>,
    pub message: Option<&'a [u8]>,
    pub addr_types: Option<u8>,
    pub addr_sources: Option<u8>,
    pub date_encoding: Option<u8>,
    pub enum_ref: Option<u16>,
    pub decimals: Option<u8>,
    pub base: Option<&'a [u8]>,
    pub prefix: Option<u8>,
    pub suffix: Option<&'a [u8]>,
    pub nested_selector: Option<&'a [u8; 4]>,
    pub nested_callee: Option<&'a [u8; 4]>,
    pub fallback_label: Option<&'a [u8]>,
    /// Constant annotation string for a path-less field. When `Some`, the
    /// renderer shows this literal text instead of resolving a path.
    pub const_value: Option<&'a [u8]>,
    /// Always populated. Defaults to `Always` when no VISIBILITY TLV is
    /// present.
    pub visibility: Visibility,
    /// Sub-TLV for `IfNotIn` / `MustMatch` value lists (Phase 5+).
    /// Phase 4 only sees this when the VISIBILITY TLV's payload is
    /// longer than 1 byte; current `dbgen` only emits a 1-byte payload.
    pub visibility_values: Option<&'a [u8]>,
    /// Set (to the raw `PARAM_NESTED_STRUCT` payload) when this field is a
    /// nested-EIP-712 struct anchor. The payload's leading version byte selects
    /// the shape: `0x01` = the bare belt marker (an unsupported nested member
    /// the device declines the WHOLE format for —
    /// `VULN-erc7730-eip712-nested-struct-address-hide`); `0x03` = the
    /// structured v0x03 descent block (`word_pos | type_hash | member_count |
    /// flags | addr_word_bmp | sub_fields`, parsed by the nested renderer).
    /// Until the belt is inverted (Phase 5 Commit D), the caller declines on
    /// EITHER form — the fail-safe.
    pub nested_struct: Option<&'a [u8]>,
    /// A `tokenAmount`'s native-currency sentinel address list
    /// (`PARAM_NATIVE_CURRENCY`): one or two concatenated 20-byte addresses in
    /// descriptor order. The renderer treats an exact match to any member as
    /// the chain native currency.
    pub native_currency_addresses: Option<&'a [u8]>,
    /// ABI type of a dynamic `FollowOffset` leaf. This is emitted by dbgen from
    /// the canonical function signature, never inferred from payload bytes.
    pub dynamic_kind: Option<u8>,
    /// Descriptor-authenticated literal NFT collection contract.
    pub nft_collection: Option<&'a [u8; 20]>,
    /// Descriptor-authenticated static path resolving the NFT collection
    /// contract (for example `@.to`).
    pub nft_collection_path: Option<&'a [u8]>,
    /// Format-level interpolation bytecode. Canonically emitted only on field
    /// ordinal zero; the IR validator enforces that placement and validates
    /// every referenced field before rendering can begin.
    pub interpolated_intent: Option<InterpolatedIntentProgram<'a>>,
    /// Mandatory for every field.  Parsed from
    /// [`PARAM_TERMINAL_KIND`] and checked by the shared host/device policy.
    pub terminal_kind: Option<TerminalKind>,
    /// Authenticated ABI integer width in bytes.  Present exactly for
    /// [`TerminalKind::Unsigned`] and [`TerminalKind::Signed`].
    pub integer_width_bytes: Option<u8>,
    /// One or two exact descriptor-authenticated address sentinels. Only the
    /// `addressName` formatter may consume this parameter.
    pub sender_addresses: Option<&'a [u8]>,
    /// Orthogonal scalar predicate evaluated format-wide before publication.
    /// It is deliberately excluded from [`ParamSet::policy_mask`] because it
    /// constrains a field without changing its formatter semantics.
    pub word_guard: Option<WordGuard<'a>>,
    /// Authenticated zero-payload assertion that this dynamic `bytes` field is
    /// accepted only when its sole canonical ABI tail is exactly empty.
    pub exact_empty_bytes: bool,
    /// Zero-based ordinal of the exact string preimage in the format's
    /// evidence traversal. Legal only for a top-level EIP-712
    /// [`TerminalKind::Eip712StringHashWord`] field; deep IR validation owns
    /// that context and path check.
    pub eip712_string_preimage_ordinal: Option<u8>,
    /// Format-level authenticated dynamic-tail topology. This is deliberately
    /// excluded from [`Self::policy_mask`]: it constrains the complete contract
    /// format rather than changing field-local formatter semantics.
    pub dynamic_tail_topology: Option<TailTopology>,
}

impl<'a> Default for ParamSet<'a> {
    fn default() -> Self {
        ParamSet {
            token_path: None,
            token: None,
            threshold: None,
            message: None,
            addr_types: None,
            addr_sources: None,
            date_encoding: None,
            enum_ref: None,
            decimals: None,
            base: None,
            prefix: None,
            suffix: None,
            nested_selector: None,
            nested_callee: None,
            fallback_label: None,
            const_value: None,
            visibility: Visibility::Always,
            visibility_values: None,
            nested_struct: None,
            native_currency_addresses: None,
            dynamic_kind: None,
            nft_collection: None,
            nft_collection_path: None,
            interpolated_intent: None,
            terminal_kind: None,
            integer_width_bytes: None,
            sender_addresses: None,
            word_guard: None,
            exact_empty_bytes: false,
            eip712_string_preimage_ordinal: None,
            dynamic_tail_topology: None,
        }
    }
}

impl ParamSet<'_> {
    /// True only when `address` exactly equals one complete authenticated
    /// native-currency sentinel. Chunk boundaries are fixed at 20 bytes, so a
    /// prefix/suffix or cross-member match is impossible.
    pub fn native_currency_matches(&self, address: &[u8; 20]) -> bool {
        self.native_currency_addresses.is_some_and(|addresses| {
            addresses
                .chunks_exact(NATIVE_CURRENCY_ADDRESS_LEN)
                .any(|candidate| candidate == address.as_slice())
        })
    }

    /// True only for an exact complete member of the authenticated
    /// `senderAddress` list.
    pub fn sender_address_matches(&self, address: &[u8; 20]) -> bool {
        self.sender_addresses.is_some_and(|addresses| {
            addresses
                .chunks_exact(SENDER_ADDRESS_LEN)
                .any(|candidate| candidate == address.as_slice())
        })
    }

    /// Whether an `addressName` field may show a verified name from the
    /// names DB instead of only the address. The DB records neither an
    /// entry's source nor its address kind, so a `sources` restriction, or a
    /// `types` restriction, can't be shown to hold for a name — except a
    /// `types` set holding both `eoa` and `contract`, which every address
    /// satisfies (Tether's USDT `approve` spender declares exactly that).
    #[must_use]
    pub const fn admits_db_name(&self) -> bool {
        let types_admit_any_address = match self.addr_types {
            None => true,
            Some(types) => types & ADDR_TYPES_ANY_ADDRESS == ADDR_TYPES_ANY_ADDRESS,
        };
        types_admit_any_address && self.addr_sources.is_none()
    }

    /// Field-local semantic parameter presence consumed by the shared
    /// formatter policy.  Visibility itself, terminal kind, and the
    /// format-level interpolation program are validated separately.
    #[must_use]
    pub const fn policy_mask(&self) -> ParamMask {
        let mut mask = ParamMask::NONE;
        if self.token_path.is_some() {
            mask = mask.union(ParamMask::TOKEN_PATH);
        }
        if self.token.is_some() {
            mask = mask.union(ParamMask::TOKEN);
        }
        if self.threshold.is_some() {
            mask = mask.union(ParamMask::THRESHOLD);
        }
        if self.message.is_some() {
            mask = mask.union(ParamMask::MESSAGE);
        }
        if self.addr_types.is_some() {
            mask = mask.union(ParamMask::ADDR_TYPES);
        }
        if self.addr_sources.is_some() {
            mask = mask.union(ParamMask::ADDR_SOURCES);
        }
        if self.date_encoding.is_some() {
            mask = mask.union(ParamMask::DATE_ENCODING);
        }
        if self.enum_ref.is_some() {
            mask = mask.union(ParamMask::ENUM_REF);
        }
        if self.decimals.is_some() {
            mask = mask.union(ParamMask::DECIMALS);
        }
        if self.base.is_some() {
            mask = mask.union(ParamMask::BASE);
        }
        if self.prefix.is_some() {
            mask = mask.union(ParamMask::PREFIX);
        }
        if self.suffix.is_some() {
            mask = mask.union(ParamMask::SUFFIX);
        }
        if self.nested_selector.is_some() {
            mask = mask.union(ParamMask::NESTED_SELECTOR);
        }
        if self.nested_callee.is_some() {
            mask = mask.union(ParamMask::NESTED_CALLEE);
        }
        if self.fallback_label.is_some() {
            mask = mask.union(ParamMask::FALLBACK_LABEL);
        }
        if self.const_value.is_some() {
            mask = mask.union(ParamMask::CONST_VALUE);
        }
        if self.visibility_values.is_some() {
            mask = mask.union(ParamMask::VISIBILITY_VALUES);
        }
        if self.nested_struct.is_some() {
            mask = mask.union(ParamMask::NESTED_STRUCT);
        }
        if self.native_currency_addresses.is_some() {
            mask = mask.union(ParamMask::NATIVE_CURRENCY);
        }
        if self.dynamic_kind.is_some() {
            mask = mask.union(ParamMask::DYNAMIC_KIND);
        }
        if self.nft_collection.is_some() {
            mask = mask.union(ParamMask::NFT_COLLECTION);
        }
        if self.nft_collection_path.is_some() {
            mask = mask.union(ParamMask::NFT_COLLECTION_PATH);
        }
        if self.sender_addresses.is_some() {
            mask = mask.union(ParamMask::SENDER_ADDRESS);
        }
        if self.exact_empty_bytes {
            mask = mask.union(ParamMask::EXACT_EMPTY_BYTES);
        }
        if self.eip712_string_preimage_ordinal.is_some() {
            mask = mask.union(ParamMask::EIP712_STRING_PREIMAGE);
        }
        mask
    }
}

fn address_list_is_canonical(payload: &[u8], max: usize) -> bool {
    let count = payload.len() / SENDER_ADDRESS_LEN;
    if payload.is_empty() || payload.len() % SENDER_ADDRESS_LEN != 0 || count > max {
        return false;
    }

    if count == 1 {
        return true;
    }

    // The reviewed bound is exactly two members, so canonical duplicate
    // detection needs one fixed comparison rather than a general nested walk.
    // This keeps both secure runtime cost and the exhaustive proof small.
    payload[..SENDER_ADDRESS_LEN] != payload[SENDER_ADDRESS_LEN..]
}

fn native_currency_list_is_canonical(payload: &[u8]) -> bool {
    address_list_is_canonical(payload, MAX_NATIVE_CURRENCY_ADDRESSES)
}

fn sender_address_list_is_canonical(payload: &[u8]) -> bool {
    address_list_is_canonical(payload, MAX_SENDER_ADDRESSES)
}

/// Parse a TLV parameter blob located at `param_off` inside the IR's
/// metadata pool. Returns the default [`ParamSet`] (everything `None`,
/// visibility `Always`) when `param_off == 0`.
pub fn parse<'a>(ir: &Erc7730Ir<'a>, param_off: u16) -> Result<ParamSet<'a>, RenderErr> {
    let mut p = ParamSet::default();
    p.visibility = Visibility::Always;

    if param_off == 0 {
        return Ok(p);
    }

    let off = param_off as usize;
    let blob_len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad param blob"))? as usize;
    let body = ir
        .pool
        .get(off + 1..off + 1 + blob_len)
        .ok_or(RenderErr::Reject("7730 bad param blob"))?;

    let mut cursor = 0usize;
    // Tags 0x30..=0x4D fit in this bitmap. Singleton parameter TLVs are
    // canonical: accepting duplicates would make meaning order-dependent and
    // previously let a short visibility duplicate retain the first tag's tail.
    let mut seen_tags = 0u32;
    while cursor < body.len() {
        if cursor + 2 > body.len() {
            return Err(RenderErr::Reject("7730 truncated tlv"));
        }
        let tag = body[cursor];
        let len = body[cursor + 1] as usize;
        cursor += 2;
        if cursor + len > body.len() {
            return Err(RenderErr::Reject("7730 tlv overrun"));
        }
        let payload = &body[cursor..cursor + len];
        cursor += len;

        if !(PARAM_TOKEN_PATH..=PARAM_DYNAMIC_TAIL_TOPOLOGY).contains(&tag) {
            return Err(RenderErr::Reject("7730 unknown tlv tag"));
        }
        let bit = 1u32 << (tag - PARAM_TOKEN_PATH);
        if seen_tags & bit != 0 {
            return Err(RenderErr::Reject("7730 duplicate tlv tag"));
        }
        seen_tags |= bit;

        match tag {
            PARAM_TOKEN_PATH => p.token_path = Some(payload),
            PARAM_TOKEN => {
                p.token = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad token"))?,
                );
            }
            PARAM_NATIVE_CURRENCY => {
                if !native_currency_list_is_canonical(payload) {
                    return Err(RenderErr::Reject("7730 bad native ccy"));
                }
                p.native_currency_addresses = Some(payload);
            }
            PARAM_DYNAMIC_KIND => {
                if payload.len() != 1
                    || !matches!(payload[0], DYNAMIC_KIND_STRING | DYNAMIC_KIND_BYTES)
                {
                    return Err(RenderErr::Reject("7730 bad dynamic kind"));
                }
                p.dynamic_kind = Some(payload[0]);
            }
            PARAM_NFT_COLLECTION => {
                p.nft_collection = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad nft collection"))?,
                );
            }
            PARAM_NFT_COLLECTION_PATH => {
                if !nft_collection_path_is_current_slice(payload) {
                    return Err(RenderErr::Reject("7730 bad nft collection path"));
                }
                p.nft_collection_path = Some(payload);
            }
            PARAM_INTERPOLATED_INTENT => {
                p.interpolated_intent = Some(InterpolatedIntentProgram::parse(payload)?);
            }
            PARAM_TERMINAL_KIND => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad terminal kind"));
                }
                p.terminal_kind = Some(
                    TerminalKind::try_from(payload[0])
                        .map_err(|_| RenderErr::Reject("7730 bad terminal kind"))?,
                );
            }
            PARAM_INTEGER_WIDTH => {
                if payload.len() != 1 || !(1..=32).contains(&payload[0]) {
                    return Err(RenderErr::Reject("7730 bad integer width"));
                }
                p.integer_width_bytes = Some(payload[0]);
            }
            PARAM_SENDER_ADDRESS => {
                if !sender_address_list_is_canonical(payload) {
                    return Err(RenderErr::Reject("7730 bad sender address"));
                }
                p.sender_addresses = Some(payload);
            }
            PARAM_WORD_GUARD => {
                if payload.len() != WORD_GUARD_PAYLOAD_LEN
                    || !matches!(payload[0], WORD_GUARD_EQ | WORD_GUARD_NE)
                {
                    return Err(RenderErr::Reject("7730 bad word guard"));
                }
                let expected = payload[1..]
                    .try_into()
                    .map_err(|_| RenderErr::Reject("7730 bad word guard"))?;
                p.word_guard = Some(WordGuard {
                    mode: payload[0],
                    expected,
                });
            }
            PARAM_EXACT_EMPTY_BYTES => {
                if !payload.is_empty() {
                    return Err(RenderErr::Reject("7730 bad exact-empty marker"));
                }
                p.exact_empty_bytes = true;
            }
            PARAM_EIP712_STRING_PREIMAGE => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad string-preimage marker"));
                }
                p.eip712_string_preimage_ordinal = Some(payload[0]);
            }
            PARAM_DYNAMIC_TAIL_TOPOLOGY => {
                p.dynamic_tail_topology = Some(TailTopology::parse(payload)?);
            }
            PARAM_THRESHOLD => {
                p.threshold = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad threshold"))?,
                );
            }
            PARAM_MESSAGE => {
                if payload.is_empty()
                    || payload.len() > 16
                    || !payload.iter().all(|&b| (0x20..0x7f).contains(&b))
                    || payload.last() == Some(&b' ')
                {
                    return Err(RenderErr::Reject("7730 bad message"));
                }
                p.message = Some(payload);
            }
            PARAM_ADDR_TYPES => {
                // wallet/eoa/contract/nft_collection/token/collection
                if payload.len() != 1 || payload[0] & !0x3f != 0 {
                    return Err(RenderErr::Reject("7730 bad addr-types"));
                }
                p.addr_types = Some(payload[0]);
            }
            PARAM_ADDR_SOURCES => {
                // local/ens/etherscan/registry
                if payload.len() != 1 || payload[0] & !0x0f != 0 {
                    return Err(RenderErr::Reject("7730 bad addr-sources"));
                }
                p.addr_sources = Some(payload[0]);
            }
            PARAM_DATE_ENCODING => {
                if payload.len() != 1 || !matches!(payload[0], 0 | 1) {
                    return Err(RenderErr::Reject("7730 bad date enc"));
                }
                p.date_encoding = Some(payload[0]);
            }
            PARAM_ENUM_REF => {
                if payload.len() != 2 {
                    return Err(RenderErr::Reject("7730 bad enum ref"));
                }
                p.enum_ref = Some(u16::from_be_bytes([payload[0], payload[1]]));
            }
            PARAM_DECIMALS => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad decimals"));
                }
                p.decimals = Some(payload[0]);
            }
            PARAM_BASE => {
                if payload.is_empty()
                    || !payload.iter().all(|&b| (0x20..0x7f).contains(&b))
                    || payload.last() == Some(&b' ')
                {
                    return Err(RenderErr::Reject("7730 bad unit base"));
                }
                p.base = Some(payload);
            }
            PARAM_PREFIX => {
                if payload != [0] {
                    return Err(RenderErr::Reject("7730 bad prefix"));
                }
                p.prefix = Some(payload[0]);
            }
            PARAM_SUFFIX => p.suffix = Some(payload),
            PARAM_NESTED_SELECTOR => {
                p.nested_selector = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad nested selector"))?,
                );
            }
            PARAM_NESTED_CALLEE => {
                p.nested_callee = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad nested callee path"))?,
                );
            }
            PARAM_FALLBACK_LABEL => {
                if payload.is_empty()
                    || !payload.iter().all(|&b| (0x20..0x7f).contains(&b))
                    || payload.last() == Some(&b' ')
                {
                    return Err(RenderErr::Reject("7730 bad fallback label"));
                }
                p.fallback_label = Some(payload);
            }
            PARAM_CONST_VALUE => {
                if payload.is_empty()
                    || !payload.iter().all(|&b| (0x20..0x7f).contains(&b))
                    || payload.last() == Some(&b' ')
                {
                    return Err(RenderErr::Reject("7730 bad const value"));
                }
                p.const_value = Some(payload);
            }
            PARAM_NESTED_STRUCT => {
                // A leading version byte selects the shape. `0x01` = bare belt
                // marker; `0x03` = structured v0x03 descent block. Any other
                // leading byte (or an empty payload) fails closed. The payload
                // is stored raw; the renderer's belt declines on either form
                // until Phase 5 Commit D inverts it to descend on `0x03`.
                match payload.first() {
                    Some(0x01) if payload.len() == 1 => p.nested_struct = Some(payload),
                    Some(0x03) => p.nested_struct = Some(payload),
                    _ => return Err(RenderErr::Reject("7730 bad nested-struct marker")),
                }
            }
            PARAM_VISIBILITY => {
                if payload.is_empty() {
                    return Err(RenderErr::Reject("7730 empty visibility"));
                }
                p.visibility = Visibility::try_from(payload[0])
                    .map_err(|_| RenderErr::Reject("7730 bad visibility"))?;
                if payload.len() > 1 {
                    p.visibility_values = Some(&payload[1..]);
                }
            }
            _ => return Err(RenderErr::Reject("7730 unknown tlv tag")),
        }
    }

    // Width is semantic only for ABI integers.  Deep IR validation separately
    // requires terminal_kind on every field, but parse is also used directly
    // by bounded tests and renderer helpers: do not let an orphan width or an
    // integer kind without its width escape from this standalone boundary.
    let is_integer = matches!(
        p.terminal_kind,
        Some(TerminalKind::Unsigned | TerminalKind::Signed)
    );
    if p.integer_width_bytes.is_some() != is_integer {
        return Err(RenderErr::Reject("7730 integer width mismatch"));
    }

    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Erc7730Ir, Visibility, HEADER_LEN, SCHEMA_VER};

    /// Build a minimal IR blob with the supplied pool bytes.
    fn ir_with_pool(pool: &[u8]) -> std::vec::Vec<u8> {
        let pool_len = pool.len() as u16;
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = 0x01; // CTX_CONTRACT
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        buf[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&((HEADER_LEN as u16) + pool_len).to_be_bytes());
        buf[130..132].copy_from_slice(&pool_len.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(pool);
        buf.push(0u8); // format count
        buf
    }

    #[test]
    fn zero_offset_returns_default() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 0).unwrap();
        assert_eq!(p.visibility, Visibility::Always);
        assert!(p.decimals.is_none());
        assert!(p.token.is_none());
        assert!(p.terminal_kind.is_none());
        assert!(p.integer_width_bytes.is_none());
        assert!(p.eip712_string_preimage_ordinal.is_none());
        assert!(p.dynamic_tail_topology.is_none());
    }

    #[test]
    fn parses_authenticated_integer_width_for_both_integer_kinds() {
        let bodies = [
            [
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::Unsigned as u8,
                PARAM_INTEGER_WIDTH,
                1,
                1,
            ],
            [
                PARAM_INTEGER_WIDTH,
                1,
                31,
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::Signed as u8,
            ],
        ];

        for (body, expected_kind, expected_width) in [
            (bodies[0], TerminalKind::Unsigned, 1),
            (bodies[1], TerminalKind::Signed, 31),
        ] {
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            let parsed = parse(&ir, 1).unwrap();
            assert_eq!(parsed.terminal_kind, Some(expected_kind));
            assert_eq!(parsed.integer_width_bytes, Some(expected_width));
        }

        let address_only = [PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8];
        let mut pool = std::vec![0xFF, address_only.len() as u8];
        pool.extend_from_slice(&address_only);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let parsed = parse(&ir, 1).unwrap();
        assert_eq!(parsed.terminal_kind, Some(TerminalKind::Address));
        assert_eq!(parsed.integer_width_bytes, None);
    }

    #[test]
    fn rejects_malformed_or_inapplicable_integer_width() {
        let cases = [
            std::vec![PARAM_INTEGER_WIDTH, 0],
            std::vec![PARAM_INTEGER_WIDTH, 2, 1, 2],
            std::vec![PARAM_INTEGER_WIDTH, 1, 0],
            std::vec![PARAM_INTEGER_WIDTH, 1, 33],
            std::vec![PARAM_TERMINAL_KIND, 1, TerminalKind::Unsigned as u8,],
            std::vec![PARAM_TERMINAL_KIND, 1, TerminalKind::Signed as u8],
            std::vec![PARAM_INTEGER_WIDTH, 1, 8],
            std::vec![
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::Address as u8,
                PARAM_INTEGER_WIDTH,
                1,
                20,
            ],
            std::vec![
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::Unsigned as u8,
                PARAM_INTEGER_WIDTH,
                1,
                8,
                PARAM_INTEGER_WIDTH,
                1,
                8,
            ],
        ];

        for body in cases {
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err(), "accepted malformed body {body:?}");
        }
    }

    #[test]
    fn interpolated_intent_program_is_strict_and_field_ordinal_bound() {
        let program = [
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
        let parsed = InterpolatedIntentProgram::parse(&program).unwrap();
        assert_eq!(parsed.substitution_count(), 1);
        assert_eq!(parsed.literal(0).unwrap(), b"Deposit ");
        assert_eq!(parsed.field_ordinal(0).unwrap(), 0);
        assert_eq!(parsed.literal(1).unwrap(), b"");
    }

    #[test]
    fn interpolated_intent_count_gate_precedes_payload_walk() {
        for count in [0, 2, 3, 4, u8::MAX] {
            let payload = [INTERPOLATED_INTENT_VERSION, count, 0];
            assert_eq!(
                InterpolatedIntentProgram::parse(&payload).unwrap_err(),
                RenderErr::Reject("7730 bad interpolation count")
            );
        }

        let canonical = [INTERPOLATED_INTENT_VERSION, 1, 0, 0, 0];
        assert!(InterpolatedIntentProgram::parse(&canonical).is_ok());
    }

    #[test]
    fn interpolated_intent_rejects_malformed_or_ambiguous_programs() {
        let cases: &[&[u8]] = &[
            &[0xFF, 1, 0, 0, 0],             // bad version
            &[1, 0, 0],                      // zero substitutions
            &[1, 4, 0, 0, 0, 1, 0, 2, 0, 3], // over the cap/truncated
            &[1, 2, 0, 0, 0, 1, 0],          // executable subset is exactly one
            &[1, 1, 1, b'{', 0, 0],          // source brace survived host compile
            &[1, 1, 0, 0],                   // missing final literal
            &[1, 1, 0, 0, 0, 0xAA],          // trailing byte
            &[1, 1, 0, 0, 1, b'x'],          // final literal must be empty
            &[1, 2, 0, 0, 0, 0, 0, 0],       // duplicate field ordinal
            &[1, 1, 1, b' ', 0, 0],          // leading display padding
            &[1, 1, 0, 0, 1, b' '],          // trailing display padding
        ];
        for payload in cases {
            assert!(
                InterpolatedIntentProgram::parse(payload).is_err(),
                "accepted malformed interpolation {payload:?}"
            );
        }
    }

    #[test]
    fn interpolated_intent_minimum_output_bound_is_exact() {
        let mut exact = std::vec![1, 1, 31];
        exact.extend_from_slice(&[b'a'; 31]);
        exact.extend_from_slice(&[0, 0]);
        assert!(InterpolatedIntentProgram::parse(&exact).is_ok());

        let mut too_long = std::vec![1, 1, 32];
        too_long.extend_from_slice(&[b'a'; 32]);
        too_long.extend_from_slice(&[0, 0]);
        assert!(InterpolatedIntentProgram::parse(&too_long).is_err());
    }

    #[test]
    fn parses_decimals_and_token() {
        // pool layout starting at offset 1 of `ir.pool` (filler at 0):
        //   filler [0xFF]
        //   blob_len = 25 (= 3 + 2 + 20)
        //   0x38 0x01 0x06                  (decimals=6, 3 bytes)
        //   0x31 0x14 <20 bytes>            (token=0xAB.., 2 + 20 bytes)
        let mut pool = std::vec![0xFFu8];
        pool.push(25);
        pool.extend_from_slice(&[0x38, 0x01, 0x06]);
        pool.extend_from_slice(&[0x31, 0x14]);
        pool.extend_from_slice(&[0xABu8; 20]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.decimals, Some(6));
        assert_eq!(p.token, Some(&[0xAB; 20]));
        assert_eq!(p.visibility, Visibility::Always);
    }

    #[test]
    fn parses_legacy_scalar_native_currency_byte_identically() {
        let sentinel = [0xEEu8; NATIVE_CURRENCY_ADDRESS_LEN];
        let mut pool = std::vec![0xFFu8, 22, PARAM_NATIVE_CURRENCY, 20];
        pool.extend_from_slice(&sentinel);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.native_currency_addresses, Some(&sentinel[..]));
        assert!(p.native_currency_matches(&sentinel));
    }

    #[test]
    fn parses_two_native_currency_addresses_and_matches_each_exactly() {
        let first = [0xEEu8; NATIVE_CURRENCY_ADDRESS_LEN];
        let second = [0x00u8; NATIVE_CURRENCY_ADDRESS_LEN];
        let mut payload = std::vec::Vec::new();
        payload.extend_from_slice(&first);
        payload.extend_from_slice(&second);
        let mut pool = std::vec![
            0xFFu8,
            (2 + payload.len()) as u8,
            PARAM_NATIVE_CURRENCY,
            payload.len() as u8,
        ];
        pool.extend_from_slice(&payload);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.native_currency_addresses, Some(&payload[..]));
        assert!(p.native_currency_matches(&first));
        assert!(p.native_currency_matches(&second));

        let mut miss = first;
        miss[NATIVE_CURRENCY_ADDRESS_LEN - 1] ^= 1;
        assert!(!p.native_currency_matches(&miss));
    }

    #[test]
    fn rejects_noncanonical_native_currency_lists() {
        for payload in [
            std::vec![0x11; 0],
            std::vec![0x11; 19],
            std::vec![0x11; 21],
            std::vec![0x11; 39],
            std::vec![0x11; 41],
            std::vec![0x11; 60],
            std::vec![0x11; 40], // two identical addresses
        ] {
            let mut pool = std::vec![
                0xFFu8,
                (2 + payload.len()) as u8,
                PARAM_NATIVE_CURRENCY,
                payload.len() as u8,
            ];
            pool.extend_from_slice(&payload);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(
                matches!(parse(&ir, 1), Err(RenderErr::Reject("7730 bad native ccy"))),
                "accepted payload length {}",
                payload.len()
            );
        }
    }

    #[test]
    fn parses_sender_addresses_and_exact_word_guards() {
        let first = [0x01u8; SENDER_ADDRESS_LEN];
        let second = [0x02u8; SENDER_ADDRESS_LEN];
        let mut expected = [0u8; 32];
        expected[31] = 7;

        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_SENDER_ADDRESS, 40]);
        body.extend_from_slice(&first);
        body.extend_from_slice(&second);
        body.extend_from_slice(&[
            PARAM_WORD_GUARD,
            WORD_GUARD_PAYLOAD_LEN as u8,
            WORD_GUARD_NE,
        ]);
        body.extend_from_slice(&expected);
        body.extend_from_slice(&[
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::Unsigned as u8,
            PARAM_INTEGER_WIDTH,
            1,
            32,
        ]);
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let parsed = parse(&ir, 1).unwrap();
        assert!(parsed.sender_address_matches(&first));
        assert!(parsed.sender_address_matches(&second));
        assert!(!parsed.sender_address_matches(&[0x03; 20]));
        let guard = parsed.word_guard.expect("guard parsed");
        assert_eq!(guard.mode(), WORD_GUARD_NE);
        assert_eq!(guard.expected(), &expected);
        assert!(!guard.accepts(&expected));
        expected[31] ^= 1;
        assert!(guard.accepts(&expected));
    }

    #[test]
    fn rejects_noncanonical_sender_lists_and_word_guards() {
        for payload in [
            std::vec![0x11; 0],
            std::vec![0x11; 19],
            std::vec![0x11; 21],
            std::vec![0x11; 40], // duplicate pair
            std::vec![0x11; 60],
        ] {
            let mut pool = std::vec![
                0xFF,
                (2 + payload.len()) as u8,
                PARAM_SENDER_ADDRESS,
                payload.len() as u8,
            ];
            pool.extend_from_slice(&payload);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(matches!(
                parse(&ir, 1),
                Err(RenderErr::Reject("7730 bad sender address"))
            ));
        }

        for payload in [
            std::vec![WORD_GUARD_EQ; 32],
            std::vec![WORD_GUARD_EQ; 34],
            {
                let mut payload = std::vec![0u8; WORD_GUARD_PAYLOAD_LEN];
                payload[0] = 2;
                payload
            },
        ] {
            let mut pool = std::vec![
                0xFF,
                (2 + payload.len()) as u8,
                PARAM_WORD_GUARD,
                payload.len() as u8,
            ];
            pool.extend_from_slice(&payload);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(matches!(
                parse(&ir, 1),
                Err(RenderErr::Reject("7730 bad word guard"))
            ));
        }
    }

    #[test]
    fn parses_nft_collection_and_collection_path() {
        let path = NFT_COLLECTION_TO_PATH;
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_NFT_COLLECTION, 20]);
        body.extend_from_slice(&[0xA4; 20]);
        body.extend_from_slice(&[PARAM_NFT_COLLECTION_PATH, path.len() as u8]);
        body.extend_from_slice(&path);
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.nft_collection, Some(&[0xA4; 20]));
        assert_eq!(p.nft_collection_path, Some(&path[..]));
    }

    #[test]
    fn extension_tags_44_45_46_have_positive_parse_controls() {
        let collection = [0xA4; 20];
        let interpolation = [INTERPOLATED_INTENT_VERSION, 1, 0, 0, 0];
        let cases: [(u8, &[u8]); 3] = [
            (PARAM_NFT_COLLECTION, &collection),
            (PARAM_NFT_COLLECTION_PATH, &NFT_COLLECTION_TO_PATH),
            (PARAM_INTERPOLATED_INTENT, &interpolation),
        ];

        for (tag, payload) in cases {
            let mut pool = std::vec![0xFF, (2 + payload.len()) as u8, tag, payload.len() as u8];
            pool.extend_from_slice(payload);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            let parsed = parse(&ir, 1).unwrap();
            match tag {
                PARAM_NFT_COLLECTION => assert_eq!(parsed.nft_collection, Some(&collection)),
                PARAM_NFT_COLLECTION_PATH => {
                    assert_eq!(
                        parsed.nft_collection_path,
                        Some(&NFT_COLLECTION_TO_PATH[..])
                    );
                }
                PARAM_INTERPOLATED_INTENT => {
                    assert!(parsed.interpolated_intent.is_some());
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn rejects_bad_or_duplicate_nft_collection_parameters() {
        for body in [
            std::vec![PARAM_NFT_COLLECTION, 19, 0x11, 0x22],
            std::vec![PARAM_NFT_COLLECTION_PATH, 0],
            std::vec![
                PARAM_NFT_COLLECTION_PATH,
                4,
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
            ],
            std::vec![
                PARAM_NFT_COLLECTION_PATH,
                4,
                PathOp::RootContainer as u8,
                PathOp::FieldIdx as u8,
                (container_field::CHAIN_ID >> 8) as u8,
                container_field::CHAIN_ID as u8,
            ],
            std::vec![
                PARAM_NFT_COLLECTION_PATH,
                1,
                0x10,
                PARAM_NFT_COLLECTION_PATH,
                1,
                0x10,
            ],
        ] {
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err(), "accepted malformed body {body:?}");
        }
    }

    #[test]
    fn parses_visibility_never() {
        let pool = std::vec![0xFFu8, 3, 0x3F, 0x01, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::Never);
        assert!(p.visibility_values.is_none());
    }

    #[test]
    fn parses_nested_struct_marker() {
        // 0x41 [0x01] → nested_struct flag set (VULN-erc7730-eip712-nested-
        // struct-address-hide on-device belt).
        let pool = std::vec![0xFFu8, 3, 0x41, 0x01, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(
            p.nested_struct,
            Some(&[0x01u8][..]),
            "bare marker stores its payload"
        );
    }

    #[test]
    fn parses_nested_struct_v3_block() {
        // 0x41 [0x03 ...] → the structured v0x03 block is stored raw for the
        // nested renderer (leading version byte 0x03).
        let pool = std::vec![0xFFu8, 4, 0x41, 0x02, 0x03, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(
            p.nested_struct,
            Some(&[0x03u8, 0x00][..]),
            "v0x03 block stored raw"
        );
    }

    #[test]
    fn default_has_no_nested_struct_flag() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(parse(&ir, 0).unwrap().nested_struct.is_none());
    }

    #[test]
    fn rejects_malformed_nested_struct_marker() {
        // Wrong payload (0x00 instead of 0x01) must fail closed.
        let pool = std::vec![0xFFu8, 3, 0x41, 0x01, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(parse(&ir, 1).is_err(), "bad marker payload rejected");
    }

    #[test]
    fn parses_visibility_with_value_list_phase_5_extension() {
        // 0x3F TLV payload length 4: [vis=MustMatch] + 3-byte sub-TLV.
        let pool = std::vec![
            0xFFu8, // filler
            6,      // blob_len
            0x3F, 0x04, 0x04, 0xAA, 0xBB, 0xCC, // VISIBILITY = MustMatch + values
        ];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::MustMatch);
        assert_eq!(p.visibility_values, Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn rejects_truncated_tlv() {
        // blob_len = 2 declares two bytes ([tag,payload_len]) but no
        // payload byte. The cursor walks past `2` declaring 1 byte of
        // payload and finds the body exhausted.
        let pool = std::vec![0xFFu8, 2, 0x38, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_unknown_tag() {
        let pool = std::vec![0xFFu8, 3, 0x7F, 0x01, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn out_of_range_offset_rejected() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 200), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_bad_decimals_width() {
        let pool = std::vec![0xFFu8, 4, 0x38, 0x02, 0x06, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_bad_token_width() {
        // PARAM_TOKEN payload must be 20 bytes; supplying 19 trips the
        // try_into → Reject path.
        let mut pool = std::vec![0xFFu8, 21, 0x31, 0x13];
        pool.extend_from_slice(&[0xAA; 19]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn parses_multiple_interleaved_tlvs() {
        // A realistic param blob: token + decimals + fallback_label +
        // visibility=Optional. Tests cursor advancement across mixed
        // payload sizes and confirms the parser doesn't drop later
        // tags after an earlier wide payload.
        let mut pool = std::vec![0xFFu8]; // filler at offset 0
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_TOKEN, 0x14]);
        body.extend_from_slice(&[0xCC; 20]);
        body.extend_from_slice(&[PARAM_DECIMALS, 0x01, 0x12]);
        let label = b"unlimited";
        body.push(PARAM_FALLBACK_LABEL);
        body.push(label.len() as u8);
        body.extend_from_slice(label);
        body.extend_from_slice(&[PARAM_VISIBILITY, 0x01, 0x02]); // Optional

        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);

        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.token, Some(&[0xCC; 20]));
        assert_eq!(p.decimals, Some(0x12));
        assert_eq!(p.fallback_label, Some(&label[..]));
        assert_eq!(p.visibility, Visibility::Optional);
        assert!(p.visibility_values.is_none());
    }

    #[test]
    fn rejects_blob_extending_past_pool() {
        // blob_len = 200 but pool only holds 50 bytes after the length
        // byte. Parser must refuse rather than read past the end.
        let mut pool = std::vec![0xFFu8, 200];
        pool.extend_from_slice(&[0x00; 50]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn parses_max_payload_tlv() {
        // Single TLV with a 252-byte payload (max single-TLV size in
        // a 254-byte blob: 1 tag + 1 len + 252 payload = 254).
        let mut pool = std::vec![0xFFu8, 254, PARAM_FALLBACK_LABEL, 252];
        pool.extend_from_slice(&[0x41u8; 252]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.fallback_label.map(|label| label.len()), Some(252));
    }

    #[test]
    fn parses_nested_selector_and_fixed_width_callee_path() {
        // Parsing preserves legacy selector syntax as untrusted input, while
        // the enrolled N2 callee is exactly one four-byte path program.
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_NESTED_SELECTOR, 0x04, 0xa9, 0x05, 0x9c, 0xbb]);
        body.extend_from_slice(&[PARAM_NESTED_CALLEE, 0x04, 0x10, 0x20, 0x00, 0x00]);
        let mut pool = std::vec![0xFFu8, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.nested_selector, Some(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(p.nested_callee, Some(&[0x10, 0x20, 0x00, 0x00]));
    }

    #[test]
    fn rejects_raw_address_or_empty_nested_callee() {
        for payload in [&[][..], &[0xDD; 20][..]] {
            let mut body = std::vec![PARAM_NESTED_CALLEE, payload.len() as u8];
            body.extend_from_slice(payload);
            let mut pool = std::vec![0xFFu8, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
        }
    }

    #[test]
    fn parses_phase5_visibility_value_list() {
        // VISIBILITY TLV with `MustMatch` byte followed by a 6-byte
        // sub-TLV (3 elements × 2-byte values). The on-wire format
        // doesn't fix the sub-TLV shape yet; the parser just stashes
        // the trailing bytes for the Phase 5 visibility evaluator.
        let mut pool = std::vec![0xFFu8, 9, PARAM_VISIBILITY, 7];
        pool.extend_from_slice(&[0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::MustMatch);
        assert_eq!(
            p.visibility_values,
            Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF][..])
        );
    }

    #[test]
    fn parses_const_value() {
        // PARAM_CONST_VALUE carries the resolved constant-annotation string.
        let label = b"Wrapped stETH";
        let mut body = std::vec::Vec::new();
        body.push(PARAM_CONST_VALUE);
        body.push(label.len() as u8);
        body.extend_from_slice(label);
        let mut pool = std::vec![0xFFu8, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.const_value, Some(&label[..]));
        assert!(p.token_path.is_none());
    }

    #[test]
    fn parses_authenticated_dynamic_kind() {
        let body = [PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING];
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            parse(&ir, 1).unwrap().dynamic_kind,
            Some(DYNAMIC_KIND_STRING)
        );
    }

    #[test]
    fn exact_empty_bytes_marker_is_zero_payload_and_singleton() {
        let body = [PARAM_EXACT_EMPTY_BYTES, 0];
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let parsed = parse(&ir, 1).unwrap();
        assert!(parsed.exact_empty_bytes);
        assert!(parsed.policy_mask().contains(ParamMask::EXACT_EMPTY_BYTES));

        for bad in [
            std::vec![PARAM_EXACT_EMPTY_BYTES, 1, 0],
            std::vec![PARAM_EXACT_EMPTY_BYTES, 0, PARAM_EXACT_EMPTY_BYTES, 0,],
        ] {
            let mut pool = std::vec![0xFF, bad.len() as u8];
            pool.extend_from_slice(&bad);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err());
        }
    }

    #[test]
    fn eip712_string_preimage_marker_is_one_byte_and_singleton() {
        let body = [PARAM_EIP712_STRING_PREIMAGE, 1, 1];
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let parsed = parse(&ir, 1).unwrap();
        assert_eq!(parsed.eip712_string_preimage_ordinal, Some(1));
        assert!(parsed
            .policy_mask()
            .contains(ParamMask::EIP712_STRING_PREIMAGE));

        for bad in [
            std::vec![PARAM_EIP712_STRING_PREIMAGE, 0],
            std::vec![PARAM_EIP712_STRING_PREIMAGE, 2, 0, 1],
            std::vec![
                PARAM_EIP712_STRING_PREIMAGE,
                1,
                0,
                PARAM_EIP712_STRING_PREIMAGE,
                1,
                1,
            ],
        ] {
            let mut pool = std::vec![0xFF, bad.len() as u8];
            pool.extend_from_slice(&bad);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err(), "accepted malformed marker {bad:?}");
        }
    }

    #[test]
    fn dynamic_tail_topology_marker_is_versioned_exact_and_format_level() {
        use crate::render::calldata_topology::{TailKind, TOPOLOGY_VERSION};

        let payload = [
            TOPOLOGY_VERSION,
            2,
            0,
            0,
            TailKind::Blob as u8,
            0,
            1,
            TailKind::StaticWordArray as u8,
        ];
        let mut body = std::vec![PARAM_DYNAMIC_TAIL_TOPOLOGY, payload.len() as u8];
        body.extend_from_slice(&payload);
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let parsed = parse(&ir, 1).unwrap();
        assert!(parsed.dynamic_tail_topology.is_some());
        assert_eq!(parsed.policy_mask(), ParamMask::NONE);

        let malformed = [
            std::vec![],
            std::vec![TOPOLOGY_VERSION + 1, 2, 0, 0, 1, 0, 1, 1],
            std::vec![TOPOLOGY_VERSION, 1, 0, 0, 1],
            std::vec![TOPOLOGY_VERSION, 2, 0, 0, 1],
            std::vec![TOPOLOGY_VERSION, 2, 0, 0, 1, 0, 1, 1, 0],
            std::vec![TOPOLOGY_VERSION, 2, 0, 1, 1, 0, 1, 1],
            std::vec![TOPOLOGY_VERSION, 2, 0, 0, 0xFF, 0, 1, 1],
        ];
        for payload in malformed {
            let mut body = std::vec![PARAM_DYNAMIC_TAIL_TOPOLOGY, payload.len() as u8];
            body.extend_from_slice(&payload);
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err(), "accepted topology {payload:?}");
        }

        let mut duplicate = std::vec![PARAM_DYNAMIC_TAIL_TOPOLOGY, payload.len() as u8];
        duplicate.extend_from_slice(&payload);
        duplicate.extend_from_slice(&[PARAM_DYNAMIC_TAIL_TOPOLOGY, payload.len() as u8]);
        duplicate.extend_from_slice(&payload);
        let mut pool = std::vec![0xFF, duplicate.len() as u8];
        pool.extend_from_slice(&duplicate);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(parse(&ir, 1).is_err());
    }

    #[test]
    fn rejects_invalid_or_duplicate_dynamic_kind() {
        for body in [
            std::vec![PARAM_DYNAMIC_KIND, 1, 0xFF],
            std::vec![
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_STRING,
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_BYTES,
            ],
        ] {
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err());
        }
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! Bounded verification of the ERC-7730 TLV parameter parser over
    //! symbolic (companion-supplied) descriptor-pool bytes.
    //!
    //! The parser reads ONLY `ir.pool`, so each harness constructs an
    //! `Erc7730Ir` whose other fields are dummy and whose `pool` is the
    //! symbolic byte array — isolating `parse` from the IR header parser
    //! (covered separately by `ir::kani_harnesses::erc7730_ir_parse_panic_free`).
    //!
    //! Bound (honest): the per-tag soundness harnesses are EXHAUSTIVE over
    //! a single TLV entry's content (symbolic tag / length / payload bytes,
    //! payload bounded to the in-pool capacity). Multi-entry *cursor-tiling
    //! fidelity* (entry N+1 begins exactly where N ended, no overlap/gap
    //! across records) is closed only for panic / slice-OOB freedom by
    //! `params_parse_panic_free`, NOT for full multi-record value soundness
    //! — the same scoping the SOTA doc applies to multiSend layer-2.

    use super::*;
    use crate::ir::ContextKind;

    /// Build an `Erc7730Ir` whose only meaningful field is `pool`. Every
    /// other field is a fixed dummy: `parse` never reads them.
    fn mk_ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: 0,
            context_kind: ContextKind::Contract,
            chain_id: 0,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    /// Panic / arithmetic-overflow / slice-OOB freedom for the whole
    /// multi-TLV walk over an arbitrary pool, an arbitrary in-bounds pool
    /// length, AND an arbitrary `param_off` (so a hostile offset cannot
    /// panic the parser either). This is the "dynamic offsets/lengths stay
    /// in-bounds — no read past end" property over the cursor loop; Kani's
    /// default checks discharge it. Bound: N-byte pool, loop unwound to N/2+1.
    #[kani::proof]
    #[kani::unwind(10)]
    fn params_parse_panic_free() {
        const N: usize = 16;
        let pool: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let off: u16 = kani::any();
        let ir = mk_ir(&pool[..len]);
        let _ = parse(&ir, off);
    }

    // ---- per-tag soundness (offset PINNED at param_off = 1) -------------
    //
    // Layout for `param_off = 1`, single TLV occupying the whole blob:
    //   pool[0]            filler (param_off points at pool[1])
    //   pool[1] = blob_len = 2 + L
    //   pool[2] = tag
    //   pool[3] = L (payload_len)
    //   pool[4 .. 4+L]     payload
    // `assume(pool[1] == 2 + L)` makes the single TLV span the whole body;
    // `assume(4 + L <= N)` keeps the payload in-pool so the only reject is
    // the per-tag width/value gate (body-overflow rejects are the
    // panic-free harness's job). All assertions reconstruct the expected
    // value from the ORIGINAL `pool` at the fixed offset — never from the
    // parser's cursor — so they cannot pass by re-checking the parser
    // against itself.

    /// `enum_ref` (0x37): accept ⟺ exactly 2 payload bytes, and the stored
    /// value is the big-endian u16 of those bytes read at the fixed offset.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_enum_ref_width_and_value_sound() {
        const N: usize = 10;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_ENUM_REF);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 2);
                assert_eq!(p.enum_ref, Some(u16::from_be_bytes([pool[4], pool[5]])));
            }
            Err(_) => assert!(l != 2),
        }
    }

    /// `decimals` (0x38): accept ⟺ exactly 1 payload byte, and the stored
    /// value is that byte read at the fixed offset.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_decimals_width_and_value_sound() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_DECIMALS);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 1);
                assert_eq!(p.decimals, Some(pool[4]));
            }
            Err(_) => assert!(l != 1),
        }
    }

    /// `token` (0x31): accept ⟺ exactly 20 payload bytes, and the stored
    /// `&[u8; 20]` is the verbatim 20-byte window at the fixed offset.
    ///
    /// The structural bytes are assigned directly and a single symbolic byte
    /// index proves all 20 payload positions. This is equivalent to whole-slice
    /// equality without bit-blasting a symbolic 20-byte `memcmp`.
    #[kani::proof]
    #[kani::unwind(6)]
    fn params_token_width_and_value_sound() {
        const N: usize = 24;
        let mut pool: [u8; N] = kani::any();
        let l: usize = kani::any();
        kani::assume(l <= 20);
        pool[0] = 0xFF;
        pool[1] = (2 + l) as u8;
        pool[2] = PARAM_TOKEN;
        pool[3] = l as u8;
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 20);
                let k: usize = kani::any();
                kani::assume(k < 20);
                assert!(p.token.is_some());
                assert!(p.token.unwrap()[k] == pool[4 + k]);
            }
            Err(_) => assert!(l != 20),
        }
    }

    /// `visibility` (0x3F): accept ⟺ non-empty payload AND a first byte in
    /// the valid Visibility range (≤ 4). On accept the variant equals
    /// `Visibility::try_from(payload[0])` and the value-list tail (Phase 5)
    /// is exactly `payload[1..]` when longer than one byte. This is the
    /// "reject out-of-range enum selector" property for the visibility byte.
    ///
    /// Unwind 10 covers the `memcmp` for the (≤ 5-byte) `visibility_values`
    /// slice comparison plus the one-iteration single-TLV walk.
    #[kani::proof]
    #[kani::unwind(10)]
    fn params_visibility_gate_and_value_sound() {
        const N: usize = 10;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_VISIBILITY);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l >= 1);
                assert!(pool[4] <= 4);
                assert_eq!(p.visibility, Visibility::try_from(pool[4]).unwrap());
                if l > 1 {
                    assert_eq!(p.visibility_values, Some(&pool[5..4 + l]));
                } else {
                    assert_eq!(p.visibility_values, None);
                }
            }
            Err(_) => assert!(l == 0 || pool[4] > 4),
        }
    }

    /// The authenticated native-currency list has exactly one of two
    /// canonical widths, and the two-member form is canonical iff its members
    /// differ. This is exhaustive over every byte through the first reachable
    /// over-capacity width (three complete addresses), so the deployed
    /// `count > MAX_NATIVE_CURRENCY_ADDRESSES` rejection is not vacuous.
    #[kani::proof]
    #[kani::unwind(24)]
    fn params_native_currency_list_canonicality() {
        const N: usize = (MAX_NATIVE_CURRENCY_ADDRESSES + 1) * NATIVE_CURRENCY_ADDRESS_LEN;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);

        const TWO_MEMBER_WIDTH: usize = MAX_NATIVE_CURRENCY_ADDRESSES * NATIVE_CURRENCY_ADDRESS_LEN;
        let expected_width = len == NATIVE_CURRENCY_ADDRESS_LEN || len == TWO_MEMBER_WIDTH;
        let members_distinct = len != TWO_MEMBER_WIDTH
            || bytes[..NATIVE_CURRENCY_ADDRESS_LEN]
                != bytes[NATIVE_CURRENCY_ADDRESS_LEN..TWO_MEMBER_WIDTH];
        assert_eq!(
            native_currency_list_is_canonical(&bytes[..len]),
            expected_width && members_distinct
        );
    }

    /// Executable interpolation v1 is deliberately one substitution with no
    /// suffix. Prove the complete parser biconditional over every payload byte
    /// and length through the first output-overflow case; this is the actual
    /// authority boundary, not a set of concrete positive/negative examples.
    #[kani::proof]
    #[kani::unwind(40)]
    fn params_interpolated_intent_executable_subset() {
        // Five framing bytes plus a 32-byte literal reaches the first value
        // rejected solely because literal bytes + one witness exceed the
        // two-row (32-cell) title budget.
        const N: usize = MAX_INTERPOLATED_INTENT_LEN + 5;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);

        let expected = if len < 5 || bytes[0] != INTERPOLATED_INTENT_VERSION || bytes[1] != 1 {
            false
        } else {
            let literal_len = bytes[2] as usize;
            if literal_len > N - 5 || len != literal_len + 5 {
                false
            } else {
                let literal = &bytes[3..3 + literal_len];
                let final_literal_len = bytes[4 + literal_len];
                literal
                    .iter()
                    .all(|&b| (0x20..0x7f).contains(&b) && !matches!(b, b'{' | b'}'))
                    && literal.first() != Some(&b' ')
                    && final_literal_len == 0
                    && literal_len + 1 <= MAX_INTERPOLATED_INTENT_LEN
            }
        };

        assert_eq!(
            InterpolatedIntentProgram::parse(&bytes[..len]).is_ok(),
            expected
        );
    }

    /// TLV 0x45 accepts the frozen `@.to` program and no other four-byte path.
    /// The full parser is exercised so this is also a non-vacuity control for
    /// the newly extended high-tag range.
    #[kani::proof]
    #[kani::unwind(10)]
    fn params_nft_collection_path_current_slice() {
        let path: [u8; 4] = kani::any();
        let mut pool = [0u8; 8];
        pool[0] = 0xFF;
        pool[1] = 6;
        pool[2] = PARAM_NFT_COLLECTION_PATH;
        pool[3] = 4;
        pool[4..].copy_from_slice(&path);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(parsed) => {
                assert!(path == NFT_COLLECTION_TO_PATH);
                assert_eq!(parsed.nft_collection_path, Some(&pool[4..]));
            }
            Err(_) => assert!(path != NFT_COLLECTION_TO_PATH),
        }
    }

    // ---- self-anchored non-vacuity controls ----------------------------

    /// Positive control: a concrete, canonical multi-TLV blob
    /// (decimals + token + visibility=Never) is ACCEPTED and decodes to
    /// exactly the expected fields. Without this every biconditional Ok
    /// branch above could in principle be vacuous; this witnesses that the
    /// parser genuinely accepts a realistic descriptor.
    ///
    /// Unwind 24: the 20-byte `memcmp` for the token value comparison
    /// dominates; the three-entry TLV walk is well within this bound.
    #[kani::proof]
    #[kani::unwind(24)]
    fn params_accepts_concrete() {
        // Whole array pre-seeded with the token payload byte (0xAB); the
        // structural bytes are then patched in. No harness-side loop.
        let mut pool = [0xABu8; 30];
        pool[0] = 0xFF; // filler
        pool[1] = 28; // blob_len = 3 (decimals) + 22 (token) + 3 (visibility)
        pool[2] = PARAM_DECIMALS;
        pool[3] = 1;
        pool[4] = 6;
        pool[5] = PARAM_TOKEN;
        pool[6] = 20;
        // pool[7..27] already 0xAB (token payload)
        pool[27] = PARAM_VISIBILITY;
        pool[28] = 1;
        pool[29] = Visibility::Never as u8;
        let ir = mk_ir(&pool);
        let p = parse(&ir, 1).expect("canonical multi-TLV param blob must decode");
        assert_eq!(p.decimals, Some(6));
        assert_eq!(p.token, Some(&[0xAB; 20]));
        assert_eq!(p.visibility, Visibility::Never);
        assert_eq!(p.visibility_values, None);
    }

    /// On-point negative: a tag outside the contiguous known tag range is
    /// REJECTED regardless of its symbolic payload — a hostile
    /// descriptor cannot smuggle an unknown TLV past the renderer.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_rejects_unknown_tag() {
        // Large enough to encode the widest adjacent known tag (the 20-byte
        // native-currency address), so the property cannot pass merely because
        // every high-tag payload is structurally truncated.
        const N: usize = 24;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        let tag = pool[2];
        // "Unknown" = outside the CONTIGUOUS known-tag range
        // `[0x30, PARAM_DYNAMIC_TAIL_TOPOLOGY]`.
        // NB: the top bound is the HIGHEST known tag, not 0x3F — new tags were added
        // above the original 0x30..=0x3F block (`PARAM_CONST_VALUE` 0x40 in b37a052f,
        // `PARAM_NESTED_STRUCT` 0x41 in 2f4cc810), so a stale bound wrongly classifies
        // a known tag as unknown and the harness fails on a tag the parser correctly
        // accepts. Keep this in sync with the highest `PARAM_*` constant.
        kani::assume(tag < PARAM_TOKEN_PATH || tag > PARAM_DYNAMIC_TAIL_TOPOLOGY);
        let ir = mk_ir(&pool);
        assert!(parse(&ir, 1).is_err());
    }

    /// The exact-empty assertion is a canonical zero-payload singleton. Any
    /// accepted one-entry marker therefore sets the boolean and has no hidden
    /// payload bytes whose meaning could be ignored by the renderer.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_exact_empty_bytes_zero_payload_sound() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let len = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + len);
        kani::assume(4 + len <= N);
        kani::assume(pool[2] == PARAM_EXACT_EMPTY_BYTES);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(params) => {
                assert!(len == 0);
                assert!(params.exact_empty_bytes);
            }
            Err(_) => assert!(len != 0),
        }
    }

    /// The schema-v6 exact-string marker is accepted only with one ordinal
    /// byte. Context, topology, ordering, and count reconciliation are owned by
    /// `Erc7730Ir::validate_formats`; this harness pins the standalone TLV
    /// parser's shape and value preservation.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_eip712_string_preimage_one_byte_sound() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let len = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + len);
        kani::assume(4 + len <= N);
        kani::assume(pool[2] == PARAM_EIP712_STRING_PREIMAGE);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(params) => {
                assert!(len == 1);
                assert!(params.eip712_string_preimage_ordinal == Some(pool[4]));
            }
            Err(_) => assert!(len != 1),
        }
    }

    /// On-point negative: a VISIBILITY TLV whose first byte is out of the
    /// valid range (> 4) is REJECTED. This is exactly the "NS supplies an
    /// out-of-range visibility selector" threat the gate exists to stop.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_rejects_visibility_byte_gt_4() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(l >= 1);
        kani::assume(pool[2] == PARAM_VISIBILITY);
        kani::assume(pool[4] > 4);
        let ir = mk_ir(&pool);
        assert!(parse(&ir, 1).is_err());
    }
}
