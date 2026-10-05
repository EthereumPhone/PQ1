//! Per-formatter renderers driven by `FormatOp` (0x01..0x0F).
//!
//! Each formatter writes 1–2 pages into the supplied [`Pages`] buffer
//! and returns `Result<(), RenderErr>`. Page budget is enforced via
//! [`Pages::push_blank`] returning `Err(())` on overflow, which we map
//! to `RenderErr::PageBudget`.
//!
//! ## Path resolution
//!
//! The render path walks compiled path programs directly (rather than through
//! the retired Phase-3 `AbiView`-based interpreter — removed 2026-07, review
//! 5.4). The reason it was never on the live path: that interpreter required
//! an `AbiView` tree describing the runtime ABI shape, and the on-device IR
//! does not carry ABI type information
//! (the host-side `dbgen` knows the format-key signature but does not
//! emit it on-wire). Phase 4 sidesteps the gap by walking the path
//! program manually, accumulating a slot offset, and reading the
//! corresponding 32-byte word straight out of `inner_data` post-
//! selector. Each formatter then re-interprets those 32 bytes per the
//! type its `FormatOp` implies (uint256, address, bool, …).
//!
//! Static types (uint*, int*, address, bytes32, bool, and static tuples) are
//! read from the exact authenticated head. Dynamic support is deliberately
//! bounded: the legacy sole C1 `bytes`/`string` or primitive-array tail remains
//! byte-identical, while a versioned format marker may authenticate two to four
//! top-level blob/static-word-array objects. The sole C2 exception is the
//! deployment-scoped Router02 packed-path mode. A format-level preflight proves
//! exact ordered tail partitioning before visibility or intent publication.
//! Dynamic tuples, aliasing, gaps, unconsumed objects, and trailing bytes hard-
//! refuse the known call; they never fall through to a less complete rendering.

use super::super::primitives::{
    amount_is_exact_at_fraction_digits, chain_name, format_u64, formatted_collapses_to_zero,
    write_addr_full, write_addr_full_or_name, write_amount_two_rows, write_line, AmountFit,
};
use super::amount_decision::{
    amount_decision, token_amount_decision, unit_decision, TokenAmountArm,
};
use crate::abi::container_field;
use crate::ir::{
    ContextKind, Erc7730Ir, FieldEntry, FormatHeader, FormatOp, PathOp, UNISWAP_ROUTER02_CHAIN_ID,
    UNISWAP_ROUTER02_MAINNET, UNISWAP_V3_EXACT_INPUT_SELECTOR, UNISWAP_V3_EXACT_OUTPUT_SELECTOR,
};
use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::U256;
// `resolve_array` (the load-bearing dynamic-array tail resolver, which reuses
// `walk`'s Kani-proven readers) lives in the host crate so it is itself
// Kani-verifiable; `render_array` is a thin renderer over its result, and the
// tests reach it as `formatters::resolve_array`.
use crate::display::{DISPLAY_COLS, MAX_PAGES};
pub use crate::render::array::resolve_array;
use crate::render::array::MAX_ARRAY_RENDER;
use crate::render::calldata_topology::{
    validate_exact_partition, TailInterval, TailKind, TailPartition, TailTopology,
};
use crate::render::params::{
    nft_collection_path_is_current_slice, parse as parse_params, ParamSet, DATE_ENC_BLOCKHEIGHT,
    DATE_ENC_TIMESTAMP, DYNAMIC_KIND_BYTES, DYNAMIC_KIND_STRING, WORD_GUARD_EQ, WORD_GUARD_NE,
};
use crate::render::policy::{integer_word_is_canonical, TerminalKind};
use crate::render::uniswap_v3_path::{parse_router02_body, Direction};
use crate::render::RenderErr;

use super::{Pages, RenderedFieldWitness};

/// Friendly scaled amounts start at six fractional digits, then widen only as
/// far as needed to preserve every authenticated base unit. The complete
/// canonical text (including the full authenticated unit) must fit the two
/// trusted value rows before any page is published.
const AMOUNT_FRIENDLY_FRACTION_DIGITS: u32 = 6;
const AMOUNT_TEXT_CAPACITY: usize = DISPLAY_COLS * 2;

/// Allocation-free canonical text shared by the amount painter and the
/// interpolated-intent witness. Keeping one object prevents a later formatter
/// change from painting one precision while the title commits to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactAmountText {
    bytes: [u8; AMOUNT_TEXT_CAPACITY],
    len: u8,
}

impl ExactAmountText {
    /// Derive the shortest exact decimal from the signed word and authenticated
    /// scale/unit. No provider/fixture string enters this decision.
    fn new(signed_word: [u8; 32], decimals: u32, unit: &[u8]) -> Option<Self> {
        if unit.iter().any(|&b| !(0x20..0x7f).contains(&b)) {
            return None;
        }

        let value = U256(signed_word);
        let mut fraction_digits = core::cmp::min(decimals, AMOUNT_FRIENDLY_FRACTION_DIGITS);
        // More than 32 meaningful fractional digits cannot fit a 32-byte text.
        // If additional digits are all zero, exactness is reached earlier and
        // trailing-zero normalization produces the same canonical text.
        let maximum = core::cmp::min(decimals, AMOUNT_TEXT_CAPACITY as u32);
        while fraction_digits <= maximum {
            if amount_is_exact_at_fraction_digits(&value, decimals, fraction_digits) {
                let mut digits = [0u8; 96];
                let digits_len =
                    value.format_decimal(decimals, fraction_digits, true, &mut digits)?;
                if formatted_collapses_to_zero(&value, &digits[..digits_len]) {
                    return None;
                }
                let separator = usize::from(!unit.is_empty());
                let text_len = digits_len.checked_add(separator)?.checked_add(unit.len())?;
                if text_len == 0 || text_len > AMOUNT_TEXT_CAPACITY {
                    return None;
                }

                let mut bytes = [0u8; AMOUNT_TEXT_CAPACITY];
                bytes[..digits_len].copy_from_slice(&digits[..digits_len]);
                let mut cursor = digits_len;
                if !unit.is_empty() {
                    bytes[cursor] = b' ';
                    cursor += 1;
                    bytes[cursor..cursor + unit.len()].copy_from_slice(unit);
                }
                return Some(Self {
                    bytes,
                    len: u8::try_from(text_len).ok()?,
                });
            }
            fraction_digits = fraction_digits.checked_add(1)?;
        }
        None
    }

    fn text(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn paint(&self, row1: &mut [u8; DISPLAY_COLS], row2: &mut [u8; DISPLAY_COLS]) {
        *row1 = [b' '; DISPLAY_COLS];
        *row2 = [b' '; DISPLAY_COLS];
        let text = self.text();
        let first = core::cmp::min(text.len(), DISPLAY_COLS);
        row1[..first].copy_from_slice(&text[..first]);
        if text.len() > first {
            row2[..text.len() - first].copy_from_slice(&text[first..]);
        }
    }

    fn witness(self) -> Option<RenderedFieldWitness> {
        RenderedFieldWitness::new(self.bytes, usize::from(self.len))
    }
}

/// Exact contract-container values available to field resolution.
///
/// Field formatters intentionally receive this narrow view instead of an
/// [`Eip1559Tx`](pqsigner_tx_core::eip1559::Eip1559Tx). A top-level transaction
/// can expose its independently bound sender and nonce, while a scoped child
/// call or EIP-712 domain deliberately leaves both unavailable. The container
/// readers below reject an unavailable value; callers must never synthesize a
/// zero nonce or sender merely to reuse the formatter path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContractContainerCtx {
    pub(super) chain_id: u64,
    pub(super) target: [u8; 20],
    pub(super) value: U256,
    from: Option<[u8; 20]>,
    nonce: Option<u64>,
}

impl ContractContainerCtx {
    /// Top-level contract call with the signed envelope nonce and an optional,
    /// independently derived signer identity.
    pub(super) const fn outer(
        chain_id: u64,
        target: [u8; 20],
        value: U256,
        nonce: u64,
        from: Option<[u8; 20]>,
    ) -> Self {
        Self {
            chain_id,
            target,
            value,
            from,
            nonce: Some(nonce),
        }
    }

    /// Scoped contract-like context with no sender or nonce authority, used by
    /// EIP-712 field rendering. Nested calls must use [`Self::child`] so their
    /// zero-value invariant is fixed by construction.
    pub(super) const fn scoped(chain_id: u64, target: [u8; 20], value: U256) -> Self {
        Self {
            chain_id,
            target,
            value,
            from: None,
            nonce: None,
        }
    }

    /// First-slice nested call context. Execution policy fixes the child value
    /// to zero and deliberately grants neither sender nor nonce authority.
    /// Keeping this constructor separate from [`Self::scoped`] prevents the
    /// nested renderer from accidentally threading a host- or parent-supplied
    /// value into the child call.
    #[allow(dead_code)] // N3a publishes the context; the bounded child renderer follows in N3b.
    pub(crate) const fn child(chain_id: u64, target: [u8; 20]) -> Self {
        Self {
            chain_id,
            target,
            value: U256::zero(),
            from: None,
            nonce: None,
        }
    }
}

#[cfg(test)]
mod container_context_tests {
    use super::*;

    #[test]
    fn child_context_is_zero_value_and_refuses_from_and_nonce() {
        let target = [0xA5; 20];
        let child = ContractContainerCtx::child(8453, target);

        assert_eq!(
            container_u256(&child, container_field::VALUE),
            Ok([0u8; 32])
        );
        assert_eq!(
            container_u256(&child, container_field::NONCE),
            Err(RenderErr::Reject("7730 nonce unbound"))
        );
        assert_eq!(
            container_addr(&child, container_field::FROM),
            Err(RenderErr::Reject("7730 from unbound"))
        );
        assert_eq!(container_addr(&child, container_field::TO), Ok(target));
    }
}

#[inline]
fn require_exact_amount_text(
    signed_word: [u8; 32],
    decimals: u32,
    unit: &[u8],
) -> Result<ExactAmountText, RenderErr> {
    ExactAmountText::new(signed_word, decimals, unit)
        .ok_or(RenderErr::Reject("7730 inexact scaled value"))
}

/// Resolved form of a path program — either a slot inside the
/// structured calldata body or a well-known envelope field.
pub(super) enum Resolved<'a> {
    /// 32-byte BE word from `body[slot * 32 .. (slot+1) * 32]`.
    Slot32(&'a [u8; 32]),
    /// `@`-rooted access; caller looks up the field on `tx`.
    Container(u16),
}

/// Contract-calldata authority selected by the format-wide preflight.
///
/// `Standard` retains the existing head-bounded scalar/C1 rules. The only
/// mode allowed to resolve C2 paths is minted after an exact Router02
/// deployment + selector + five-field IR check and a whole-body ABI/path
/// parse. Direction is derived from that signed selector, never from a
/// descriptor parameter or companion-controlled byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContractCalldataMode {
    Standard,
    MultiTail(TailPartition),
    UniswapV3Path(Direction),
}

/// Walk a path program (length-prefixed at `ir.pool[path_off]`) and
/// produce a [`Resolved`] reference. Fails on:
///
/// - empty / missing path (`path_off == 0` or pool out-of-range);
/// - unsupported root (`$` metadata);
/// - non-`FieldIdx` descent (`ArrayIdx`/`ArrayLast`/`ArrayAll`/
///   `ArraySlice` — Phase 4 only renders static-tuple paths);
/// - slot offset past the supplied `body`.
pub(super) fn resolve_path<'a>(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    body: &'a [u8],
) -> Result<Resolved<'a>, RenderErr> {
    if path_off == 0 {
        return Err(RenderErr::Reject("7730 missing path"));
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }

    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let p = 1usize;

    match root {
        PathOp::RootStructured => {
            // Navigation ops (`FieldIdx` / `FollowOffset`) → the leaf's byte
            // position. A pure-static-head path (FieldIdx-only) resolves to the
            // same slot-sum word the legacy resolver read (byte-identical — the
            // slot-confusion tests pin this); `FollowOffset` adds tuple / dynamic
            // tail-follow (C1/C2). `body` is head-bounded for static fields and
            // the full body for `FollowOffset` fields (routed in `render_fields`).
            match crate::render::resolve::resolve_structured(&prog[p..], body)? {
                crate::render::resolve::Leaf::Word(off) => {
                    let word = body
                        .get(off..off + 32)
                        .ok_or(RenderErr::Reject("7730 short body"))?;
                    Ok(Resolved::Slot32(<&[u8; 32]>::try_from(word).unwrap()))
                }
                // A dynamic (`bytes`/`string`) leaf is not a scalar word: the
                // dynamic-leaf renderer handles it via `resolve_dynamic`.
                crate::render::resolve::Leaf::Dynamic(_) => {
                    Err(RenderErr::Reject("7730 dyn leaf not scalar"))
                }
            }
        }
        PathOp::RootContainer => {
            if p + 3 > prog.len() {
                return Err(RenderErr::Reject("7730 trunc cnt"));
            }
            if prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad op"));
            }
            let field_idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            // Tail must be empty (we only support a single `@.<name>`
            // step in Phase 4 — sub-fields of the envelope are not a
            // thing for any current ERC-7730 descriptor).
            if p + 3 != prog.len() {
                return Err(RenderErr::Reject("7730 cnt deep"));
            }
            Ok(Resolved::Container(field_idx))
        }
        PathOp::RootMetadata => Err(RenderErr::Reject("7730 $ root unsup")),
        PathOp::FieldIdx
        | PathOp::ArrayIdx
        | PathOp::ArrayLast
        | PathOp::ArraySlice
        | PathOp::ArrayAll
        | PathOp::FollowOffset => Err(RenderErr::Reject("7730 path no root")),
    }
}

/// Enforce the authenticated Solidity integer width against one ABI word.
///
/// This is deliberately formatter-independent: `raw`, scaled amounts, enums,
/// dates, and every future integer sink must reject the same dirty zero/sign
/// extension instead of masking or truncating it. `ParamSet` parsing and the
/// deep IR validator already enforce the tag relationship; the checks here are
/// retained as a local fault-containment belt at the publication boundary.
fn require_integer_word_canonical(params: &ParamSet<'_>, word: &[u8; 32]) -> Result<(), RenderErr> {
    match params.terminal_kind {
        Some(kind @ (TerminalKind::Unsigned | TerminalKind::Signed)) => {
            let width = params
                .integer_width_bytes
                .ok_or(RenderErr::Reject("7730 integer width missing"))?;
            if !integer_word_is_canonical(kind, width, word) {
                return Err(RenderErr::Reject("7730 noncanonical integer"));
            }
        }
        _ if params.integer_width_bytes.is_some() => {
            return Err(RenderErr::Reject("7730 integer width on noninteger"));
        }
        _ => {}
    }
    Ok(())
}

/// Resolve one scalar field and apply the width check before a formatter can
/// mutate the transcript buffer. Firmware-owned container integers are always
/// authenticated as 32-byte values, so every container word is canonical.
fn require_integer_path_canonical(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    body: &[u8],
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    if !matches!(
        params.terminal_kind,
        Some(TerminalKind::Unsigned | TerminalKind::Signed)
    ) {
        return Ok(());
    }
    match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(word) => require_integer_word_canonical(params, word),
        Resolved::Container(_) if params.integer_width_bytes == Some(32) => Ok(()),
        Resolved::Container(_) => Err(RenderErr::Reject("7730 narrow container integer")),
    }
}

/// EIP-712 top-level integer preflight. All member words, including hidden
/// fields, are checked before the authenticated intent banner is buffered.
/// Nested anchors carry no integer width; their elementary words are checked
/// after hash binding by `render::nested::validate_nested_integer_words`.
pub(crate) fn validate_eip712_integer_words(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    body: &[u8],
) -> Result<(), RenderErr> {
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        if params.nested_struct.is_none() {
            require_integer_path_canonical(ir, &field, body, &params)?;
        }
    }
    Ok(())
}

/// Read a container field value (u256-shaped) by its keccak-prefix
/// index. Returns a 32-byte BE word equivalent for the formatter to
/// re-interpret.
pub(super) fn container_u256(
    container: &ContractContainerCtx,
    idx: u16,
) -> Result<[u8; 32], RenderErr> {
    match idx {
        container_field::VALUE => Ok(container.value.0),
        container_field::CHAIN_ID => {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&container.chain_id.to_be_bytes());
            Ok(b)
        }
        container_field::NONCE => {
            let nonce = container
                .nonce
                .ok_or(RenderErr::Reject("7730 nonce unbound"))?;
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&nonce.to_be_bytes());
            Ok(b)
        }
        _ => Err(RenderErr::Reject("7730 cnt no u256")),
    }
}

/// Read a container field for the `raw` formatter. Address-valued `@.from`
/// is ABI-word encoded (12 zero bytes followed by the 20-byte sender), while
/// numeric formatters continue to reject it through [`container_u256`].
fn container_raw_word(container: &ContractContainerCtx, idx: u16) -> Result<[u8; 32], RenderErr> {
    if idx == container_field::FROM {
        let sender = container
            .from
            .as_ref()
            .ok_or(RenderErr::Reject("7730 from unbound"))?;
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(sender);
        return Ok(word);
    }
    container_u256(container, idx)
}

/// Read a container field as an address. Returns the 20-byte slice for
/// `@.to` / `@.from`.
pub(super) fn container_addr(
    container: &ContractContainerCtx,
    idx: u16,
) -> Result<[u8; 20], RenderErr> {
    match idx {
        container_field::TO => Ok(container.target),
        // `@.from` is the AA wallet's own address. It is populated only by the
        // secure UserOp handlers after mnemonic derivation and sender binding;
        // native transactions and EIP-712 synthetic envelopes have no
        // `userop_fields` and therefore still fail closed here.
        container_field::FROM => container.from.ok_or(RenderErr::Reject("7730 from unbound")),
        _ => Err(RenderErr::Reject("7730 cnt no addr")),
    }
}

/// Executable route selected for each stable [`FormatOp`] wire value.
///
/// The dispatcher below matches on this type, so the generated companion
/// semantic manifest is derived from the same route that production executes,
/// rather than from a parallel prose list.  The two `HardRefuse*` routes are
/// deliberate reserved branches: they authenticate the opcode but never
/// produce confirmable clear-sign pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum FormatterRoute {
    Raw,
    Amount,
    TokenAmount,
    NftName,
    Date,
    Duration,
    AddressName,
    Enum,
    Unit,
    HardRefuseCalldata,
    ChainId,
    TokenTicker,
    InteroperableAddressName,
    HardRefuseEncrypted,
    UniswapV3Path,
}

impl FormatterRoute {
    const IMPLEMENTED_STATUS: &'static str = "implemented renderer (fail closed on invalid input)";

    /// Short, generated-documentation wording for the production route.
    ///
    /// Keep every variant explicit: adding a production route must fail to
    /// compile until its generated-manifest classification is reviewed.
    #[must_use]
    #[doc(hidden)]
    pub const fn manifest_status(self) -> &'static str {
        match self {
            Self::Raw => Self::IMPLEMENTED_STATUS,
            Self::Amount => Self::IMPLEMENTED_STATUS,
            Self::TokenAmount => Self::IMPLEMENTED_STATUS,
            Self::NftName => Self::IMPLEMENTED_STATUS,
            Self::Date => Self::IMPLEMENTED_STATUS,
            Self::Duration => Self::IMPLEMENTED_STATUS,
            Self::AddressName => Self::IMPLEMENTED_STATUS,
            Self::Enum => Self::IMPLEMENTED_STATUS,
            Self::Unit => Self::IMPLEMENTED_STATUS,
            Self::HardRefuseCalldata => {
                "one-level proof-set child renderer for exact firmware enrollments; otherwise hard refusal (production enrollments: 0)"
            }
            Self::ChainId => Self::IMPLEMENTED_STATUS,
            Self::TokenTicker => Self::IMPLEMENTED_STATUS,
            Self::InteroperableAddressName => Self::IMPLEMENTED_STATUS,
            Self::HardRefuseEncrypted => "hard refusal (signed operand hidden)",
            Self::UniswapV3Path => Self::IMPLEMENTED_STATUS,
        }
    }
}

/// Map the canonical wire opcode to the route used by [`dispatch`].
#[must_use]
#[doc(hidden)]
pub const fn formatter_route(op: FormatOp) -> FormatterRoute {
    match op {
        FormatOp::Raw => FormatterRoute::Raw,
        FormatOp::Amount => FormatterRoute::Amount,
        FormatOp::TokenAmount => FormatterRoute::TokenAmount,
        FormatOp::NftName => FormatterRoute::NftName,
        FormatOp::Date => FormatterRoute::Date,
        FormatOp::Duration => FormatterRoute::Duration,
        FormatOp::AddressName => FormatterRoute::AddressName,
        FormatOp::Enum => FormatterRoute::Enum,
        FormatOp::Unit => FormatterRoute::Unit,
        FormatOp::Calldata => FormatterRoute::HardRefuseCalldata,
        FormatOp::ChainId => FormatterRoute::ChainId,
        FormatOp::TokenTicker => FormatterRoute::TokenTicker,
        FormatOp::InteroperableAddressName => FormatterRoute::InteroperableAddressName,
        FormatOp::Encrypted => FormatterRoute::HardRefuseEncrypted,
        FormatOp::UniswapV3Path => FormatterRoute::UniswapV3Path,
    }
}

/// Dispatcher — one renderer per `FormatOp`. Step 3 reads
/// `field.format_op`, parses params, walks the path, and emits 1–2
/// pages. Visibility filtering happens in the entry-point loop.
pub(super) fn dispatch(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<Option<RenderedFieldWitness>, RenderErr> {
    let op =
        FormatOp::try_from(field.format_op).map_err(|_| RenderErr::Reject("7730 bad format op"))?;
    // A constant-annotation field carries no path; render its literal
    // descriptor-pinned string directly, bypassing the format-op
    // path resolution (which would reject on the absent path). Its shape is
    // deliberately canonical: an authenticated-but-malformed IR must not use
    // const precedence to ignore a real signed field or an unknown formatter.
    if let Some(cv) = params.const_value {
        if op != FormatOp::Raw || field.path_off != 0 || !const_params_are_canonical(params) {
            return Err(RenderErr::Reject("7730 bad const shape"));
        }
        return render_const(field, pages, cv).map(|()| None);
    }
    if field.path_off == 0 {
        return Err(RenderErr::Reject("7730 missing field path"));
    }
    require_integer_path_canonical(ir, field, body, params)?;
    match formatter_route(op) {
        FormatterRoute::Raw => render_raw(field, pages, ir, body, container, params).map(|()| None),
        FormatterRoute::Amount => render_amount(field, pages, ir, body, container, params),
        FormatterRoute::TokenAmount => {
            render_token_amount(field, pages, ir, body, container, erc20, resolver, params)
        }
        FormatterRoute::NftName => {
            render_nft_name(field, pages, ir, body, container, resolver, params).map(|()| None)
        }
        FormatterRoute::Date => {
            render_date(field, pages, ir, body, container, params).map(|()| None)
        }
        FormatterRoute::Duration => {
            render_duration(field, pages, ir, body, container).map(|()| None)
        }
        FormatterRoute::AddressName => {
            render_address_name(field, pages, ir, body, container, resolver, params).map(|()| None)
        }
        FormatterRoute::Enum => {
            render_enum(field, pages, ir, body, container, params).map(|()| None)
        }
        FormatterRoute::Unit => {
            // The current painter supports the standard suffix placement only.
            // Do not silently ignore a descriptor requesting a prefix or an
            // additional suffix: that changes the human meaning of the number.
            if params.prefix.is_some_and(|v| v != 0) || params.suffix.is_some() {
                return Err(RenderErr::Reject("7730 unit affix unsupported"));
            }
            render_unit(field, pages, ir, body, container, params).map(|()| None)
        }
        FormatterRoute::HardRefuseCalldata => {
            super::calldata_nested::render(field, pages, params).map(|()| None)
        }
        FormatterRoute::ChainId => {
            render_chain_id(field, pages, ir, body, container).map(|()| None)
        }
        FormatterRoute::TokenTicker => {
            render_token_ticker(field, pages, ir, body, container, erc20, resolver, params)
                .map(|()| None)
        }
        FormatterRoute::InteroperableAddressName => {
            render_interop_address_name(field, pages, ir, body, container, resolver).map(|()| None)
        }
        FormatterRoute::HardRefuseEncrypted => {
            render_encrypted(field, pages, params).map(|()| None)
        }
        // The complete packed-path renderer needs the full canonically framed
        // Router02 body plus the selected format's signed selector. The
        // format-level caller intercepts this route after its exact C2
        // preflight; reaching the scalar dispatcher is always a refusal.
        FormatterRoute::UniswapV3Path => {
            Err(RenderErr::Reject("7730 v3 path missing format context"))
        }
    }
}

const ROUTER02_SENDER_SENTINEL: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ROUTER02_ZERO_WORD: [u8; 32] = [0u8; 32];
const ROUTER02_ADDRESS_TWO_WORD: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];

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

fn router02_packed_token_path(path: &[u8], member: u16) -> bool {
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

fn router02_container_value_path(path: &[u8]) -> bool {
    let value = container_field::VALUE.to_be_bytes();
    path == [
        PathOp::RootContainer as u8,
        PathOp::FieldIdx as u8,
        value[0],
        value[1],
    ]
}

fn router02_guard_matches(params: &ParamSet<'_>, mode: u8, expected: &[u8; 32]) -> bool {
    params
        .word_guard
        .is_some_and(|guard| guard.mode() == mode && guard.expected() == expected)
}

fn mark_router02_role(seen: &mut u8, role: u8) -> Result<(), RenderErr> {
    if *seen & role != 0 {
        return Err(RenderErr::Reject("7730 v3 duplicate field role"));
    }
    *seen |= role;
    Ok(())
}

/// Reconstruct the only C2 authority admitted by the device directly from the
/// authenticated IR and the actual transaction. This intentionally duplicates
/// the deep IR parser's belt at the point where full calldata becomes readable:
/// a future generic C2 formatter cannot acquire this mode by selector alone.
fn validate_uniswap_v3_runtime_format(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    container: &ContractContainerCtx,
) -> Result<Direction, RenderErr> {
    if !matches!(ir.context_kind, ContextKind::Contract)
        || ir.chain_id != UNISWAP_ROUTER02_CHAIN_ID
        || ir.contract != UNISWAP_ROUTER02_MAINNET
        || container.chain_id != UNISWAP_ROUTER02_CHAIN_ID
        || container.target != UNISWAP_ROUTER02_MAINNET
        || format.static_head_words != 1
        || format.field_count != 5
        || format.nested_descent_count != 0
    {
        return Err(RenderErr::Reject("7730 v3 identity mismatch"));
    }
    let direction = match format.selector {
        UNISWAP_V3_EXACT_INPUT_SELECTOR => Direction::Forward,
        UNISWAP_V3_EXACT_OUTPUT_SELECTOR => Direction::Reverse,
        _ => return Err(RenderErr::Reject("7730 v3 selector mismatch")),
    };

    const VALUE: u8 = 1 << 0;
    const AMOUNT_2: u8 = 1 << 1;
    const AMOUNT_3: u8 = 1 << 2;
    const PATH: u8 = 1 << 3;
    const RECIPIENT: u8 = 1 << 4;
    const ALL: u8 = VALUE | AMOUNT_2 | AMOUNT_3 | PATH | RECIPIENT;
    let mut seen = 0u8;

    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let op = FormatOp::try_from(field.format_op)
            .map_err(|_| RenderErr::Reject("7730 bad format op"))?;
        let params = parse_params(ir, field.param_off)?;
        if params.visibility != crate::ir::Visibility::Always
            || params.interpolated_intent.is_some()
        {
            return Err(RenderErr::Reject("7730 v3 field not unconditional"));
        }
        let path = ir
            .path_bytes(field.path_off)
            .map_err(|_| RenderErr::Reject("7730 v3 bad field path"))?;
        match op {
            FormatOp::Amount => {
                if !router02_container_value_path(path)
                    || params.terminal_kind != Some(TerminalKind::Unsigned)
                    || params.integer_width_bytes != Some(32)
                    || !router02_guard_matches(&params, WORD_GUARD_EQ, &ROUTER02_ZERO_WORD)
                {
                    return Err(RenderErr::Reject("7730 v3 bad native value field"));
                }
                mark_router02_role(&mut seen, VALUE)?;
            }
            FormatOp::TokenAmount => {
                if params.terminal_kind != Some(TerminalKind::Unsigned)
                    || params.integer_width_bytes != Some(32)
                {
                    return Err(RenderErr::Reject("7730 v3 bad amount kind"));
                }
                let member = if router02_packed_member_path(path, 2, false) {
                    mark_router02_role(&mut seen, AMOUNT_2)?;
                    2
                } else if router02_packed_member_path(path, 3, false) {
                    mark_router02_role(&mut seen, AMOUNT_3)?;
                    3
                } else {
                    return Err(RenderErr::Reject("7730 v3 bad amount path"));
                };
                if !params
                    .token_path
                    .is_some_and(|token_path| router02_packed_token_path(token_path, member))
                {
                    return Err(RenderErr::Reject("7730 v3 bad amount token path"));
                }
                let guard_ok = match (direction, member) {
                    (Direction::Forward, 2) => {
                        router02_guard_matches(&params, WORD_GUARD_NE, &ROUTER02_ZERO_WORD)
                    }
                    _ => params.word_guard.is_none(),
                };
                if !guard_ok {
                    return Err(RenderErr::Reject("7730 v3 bad amount guard"));
                }
            }
            FormatOp::AddressName => {
                if !router02_packed_member_path(path, 1, false)
                    || params.terminal_kind != Some(TerminalKind::Address)
                    || params.sender_addresses != Some(&ROUTER02_SENDER_SENTINEL[..])
                    || !router02_guard_matches(&params, WORD_GUARD_NE, &ROUTER02_ADDRESS_TWO_WORD)
                {
                    return Err(RenderErr::Reject("7730 v3 bad recipient field"));
                }
                mark_router02_role(&mut seen, RECIPIENT)?;
            }
            FormatOp::UniswapV3Path => {
                if !router02_packed_member_path(path, 0, true)
                    || params.terminal_kind != Some(TerminalKind::DynamicBytes)
                    || params.dynamic_kind != Some(DYNAMIC_KIND_BYTES)
                    || params.word_guard.is_some()
                {
                    return Err(RenderErr::Reject("7730 v3 bad route field"));
                }
                mark_router02_role(&mut seen, PATH)?;
            }
            _ => return Err(RenderErr::Reject("7730 v3 unexpected field")),
        }
    }
    if seen != ALL {
        return Err(RenderErr::Reject("7730 v3 incomplete field roles"));
    }
    Ok(direction)
}

pub(super) fn router02_c2_scalar_field(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    params: &ParamSet<'_>,
) -> Result<bool, RenderErr> {
    let path = ir
        .path_bytes(field.path_off)
        .map_err(|_| RenderErr::Reject("7730 v3 bad scalar path"))?;
    let op =
        FormatOp::try_from(field.format_op).map_err(|_| RenderErr::Reject("7730 bad format op"))?;
    Ok(match op {
        FormatOp::AddressName => router02_packed_member_path(path, 1, false),
        FormatOp::TokenAmount => {
            let member = if router02_packed_member_path(path, 2, false) {
                2
            } else if router02_packed_member_path(path, 3, false) {
                3
            } else {
                return Ok(false);
            };
            params
                .token_path
                .is_some_and(|token_path| router02_packed_token_path(token_path, member))
        }
        _ => false,
    })
}

/// Paint every token and fee in display/execution order. No summary page is
/// added: five hops already require eleven injective route pages, and retaining
/// the existing 31-page transaction cap is part of the fail-closed envelope.
pub(super) fn render_uniswap_v3_path(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    direction: Direction,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let path_program = ir
        .path_bytes(field.path_off)
        .map_err(|_| RenderErr::Reject("7730 v3 bad route path"))?;
    if field.format_op != FormatOp::UniswapV3Path as u8
        || !router02_packed_member_path(path_program, 0, true)
        || params.terminal_kind != Some(TerminalKind::DynamicBytes)
        || params.dynamic_kind != Some(DYNAMIC_KIND_BYTES)
    {
        return Err(RenderErr::Reject("7730 v3 route mismatch"));
    }

    // Parse the complete body before the first route page. This is a local belt
    // behind the identical format-wide preflight and keeps this renderer safe
    // if a future caller bypasses that entry point.
    let path = parse_router02_body(full_body)?;
    let hops = path.hop_count();
    for index in 0..=hops {
        let token = path.token(index, direction)?;
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_line(pages.row_mut(p, 0), "Route");
        let [_, r1, r2, r3] = pages.page_mut(p);
        write_addr_full(r1, r2, r3, &token);

        if index < hops {
            let fee = path.fee(index, direction)?;
            let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
            write_line(pages.row_mut(p, 0), "Pool fee (ppm)");
            write_u64_with_suffix(pages.row_mut(p, 1), u64::from(fee), b" ppm")?;
        }
    }
    Ok(())
}

fn write_u64_with_suffix(
    row: &mut [u8; DISPLAY_COLS],
    value: u64,
    suffix: &[u8],
) -> Result<(), RenderErr> {
    let mut digits = [0u8; 20];
    let len = format_u64(value, &mut digits).ok_or(RenderErr::Reject("7730 v3 fee"))?;
    let end = len
        .checked_add(suffix.len())
        .ok_or(RenderErr::Reject("7730 v3 fee"))?;
    if end > DISPLAY_COLS {
        return Err(RenderErr::Reject("7730 v3 fee"));
    }
    *row = [b' '; DISPLAY_COLS];
    row[..len].copy_from_slice(&digits[..len]);
    row[len..end].copy_from_slice(suffix);
    Ok(())
}

/// Constant annotations may carry visibility, but no formatter-specific
/// parameter. This closes the precedence gadget where a `const_value` made the
/// dispatcher silently ignore token paths, scaling, nested-call metadata, etc.
fn const_params_are_canonical(params: &ParamSet<'_>) -> bool {
    params.token_path.is_none()
        && params.token.is_none()
        && params.threshold.is_none()
        && params.message.is_none()
        && params.addr_types.is_none()
        && params.addr_sources.is_none()
        && params.date_encoding.is_none()
        && params.enum_ref.is_none()
        && params.decimals.is_none()
        && params.base.is_none()
        && params.prefix.is_none()
        && params.suffix.is_none()
        && params.nested_selector.is_none()
        && params.nested_callee.is_none()
        && params.fallback_label.is_none()
        && params.visibility_values.is_none()
        && params.nested_struct.is_none()
        && params.native_currency_addresses.is_none()
        && params.dynamic_kind.is_none()
        && !params.exact_empty_bytes
        && params.nft_collection.is_none()
        && params.nft_collection_path.is_none()
}

/// A dynamic ABI string is a special case of `raw`: the exact authenticated
/// bytes are painted as text plus an explicit length. No semantic formatter
/// parameter may survive this routing shortcut, otherwise an IR could request
/// `amount`/`addressName`/`unit` semantics and have them silently ignored.
fn dynamic_string_params_are_canonical(params: &ParamSet<'_>) -> bool {
    params.token_path.is_none()
        && params.token.is_none()
        && params.threshold.is_none()
        && params.message.is_none()
        && params.addr_types.is_none()
        && params.addr_sources.is_none()
        && params.date_encoding.is_none()
        && params.enum_ref.is_none()
        && params.decimals.is_none()
        && params.base.is_none()
        && params.prefix.is_none()
        && params.suffix.is_none()
        && params.nested_selector.is_none()
        && params.nested_callee.is_none()
        && params.fallback_label.is_none()
        && params.const_value.is_none()
        && params.nested_struct.is_none()
        && params.native_currency_addresses.is_none()
        && params.dynamic_kind == Some(DYNAMIC_KIND_STRING)
        && !params.exact_empty_bytes
        && params.nft_collection.is_none()
        && params.nft_collection_path.is_none()
}

/// The only admitted raw dynamic-`bytes` meaning is an authenticated exact
/// empty callback. No unrelated field or format semantics may coexist with
/// the marker and be silently ignored by this specialized painter.
fn exact_empty_bytes_params_are_canonical(params: &ParamSet<'_>) -> bool {
    params.policy_mask()
        == crate::render::policy::ParamMask::DYNAMIC_KIND
            .union(crate::render::policy::ParamMask::EXACT_EMPTY_BYTES)
        && params.dynamic_kind == Some(DYNAMIC_KIND_BYTES)
        && params.exact_empty_bytes
        && params.visibility == crate::ir::Visibility::Always
        && params.interpolated_intent.is_none()
        && params.integer_width_bytes.is_none()
        && params.word_guard.is_none()
        && params.terminal_kind == Some(TerminalKind::DynamicBytes)
}

/// `nftName` is an exact token-id renderer plus an authenticated collection
/// identity. The existing token/token-path TLVs carry the descriptor's
/// `collection`/`collectionPath` respectively; exactly one must be present and
/// no unrelated formatter semantics may be smuggled alongside it.
fn nft_params_are_canonical(params: &ParamSet<'_>) -> bool {
    (params.nft_collection_path.is_some() ^ params.nft_collection.is_some())
        && params.token_path.is_none()
        && params.token.is_none()
        && params.threshold.is_none()
        && params.message.is_none()
        && params.addr_types.is_none()
        && params.addr_sources.is_none()
        && params.date_encoding.is_none()
        && params.enum_ref.is_none()
        && params.decimals.is_none()
        && params.base.is_none()
        && params.prefix.is_none()
        && params.suffix.is_none()
        && params.nested_selector.is_none()
        && params.nested_callee.is_none()
        && params.fallback_label.is_none()
        && params.const_value.is_none()
        && params.nested_struct.is_none()
        && params.native_currency_addresses.is_none()
        && params.dynamic_kind.is_none()
        && !params.exact_empty_bytes
}

// ─────────────────────────────────────────────────────────────────────
// Per-FormatOp renderers
// ─────────────────────────────────────────────────────────────────────

fn render_raw(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        // Propagate the Reject instead of rendering a zero word for an
        // unsupported container (finding F4): `unwrap_or([0u8; 32])` showed an
        // all-zero 32-byte value while the signed UserOp committed a nonzero
        // one (e.g. raw `@.to`). Fail closed.
        Resolved::Container(idx) => container_raw_word(container, idx)?,
    };
    // A 16-col row holds 16 hex chars = 8 bytes, so the full 32-byte signed
    // word needs FOUR hex rows across two pages, so EVERY signed byte is shown
    // (WYSIWYS magnitude-hiding; fixed 2026-06-26). Shared with the
    // array-element Raw path via `write_raw_word_two_pages` so they can't
    // diverge again. Page budget is enforced by `push_blank`'s PageBudget error.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    write_raw_word_two_pages(pages, p, field.label, &bytes)
}

fn render_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<Option<RenderedFieldWitness>, RenderErr> {
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let value = U256(raw);
    // WHICH decimals/ticker paint — the pure, ∀-proven decision half (M4
    // factoring). Descriptor-pinned decimals are authoritative. Without them,
    // only a chain in the firmware's audited native table may inherit 18;
    // unknown chains render the exact raw integer instead of an assumed scale.
    // See `amount_decision::amount_decision`.
    let Some(d) = amount_decision(container.chain_id, params) else {
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, p, field.label);
        let fit = {
            let [_, r1, r2, foot] = pages.page_mut(p);
            let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, true, "");
            if fit == AmountFit::Full {
                write_line(foot, "! raw, dec=?");
            }
            fit
        };
        return if fit == AmountFit::Full {
            Ok(None)
        } else {
            write_raw_word_two_pages(pages, p, field.label, &raw).map(|()| None)
        };
    };
    // Derive the complete exact text before the first page append (and
    // therefore before transcript/CFI publication). The same bytes paint the
    // field and, when enrolled, become the interpolated-title witness.
    let amount_text = require_exact_amount_text(raw, d.decimals, d.unit)?;
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    {
        let [_, r1, r2, foot] = pages.page_mut(p);
        amount_text.paint(r1, r2);
        write_line(foot, "> next");
        pages.mark_nav(p, 3);
    }
    Ok(amount_text.witness())
}

fn render_token_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<Option<RenderedFieldWitness>, RenderErr> {
    // Resolve the amount slot.
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let value = U256(raw);

    // Resolve token contract address (params.tokenPath wins; falls
    // back to params.token literal). Used to decide which decimals /
    // symbol to display.
    let token_addr = if params.token_path.is_some() || params.token.is_some() {
        Some(resolve_token_address(ir, body, container, params)?)
    } else {
        None
    };

    // WHICH arm paints — the pure, ∀-proven decision half (M4 factoring;
    // Kani closes it without ever seeing the format_decimal paint path).
    // The full ladder rationale lives on
    // `amount_decision::token_amount_decision`: native-sentinel precedence
    // over the erc20 bundle, descriptor/known-chain-only native decimals,
    // Merkle-bound-only ERC-20 decimals/symbol, the
    // threshold gate HOISTED ABOVE the bound match (review 4.5), the
    // validated `message` override (review 3.6), the M-4 raw fallback and
    // the MEDIUM-1 identity-page rule.
    let decision = token_amount_decision(&raw, token_addr, erc20, container.chain_id, params);

    // Every `Bound` arm has an authenticated scale. Build its complete exact
    // text before any page or identity publication; semantic threshold arms
    // paint no amount, and unknown-scale arms retain exact raw rendering.
    let bound_text = match &decision.arm {
        TokenAmountArm::Bound { decimals, ticker } => {
            Some(require_exact_amount_text(raw, *decimals, ticker)?)
        }
        _ => None,
    };

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let mut raw_fallback = false;
    let mut witness = None;
    // A ticker is not an injective token identity: the authenticated catalogue
    // can contain distinct contracts with identical symbol/decimals. Every
    // bound non-native token therefore gets a full contract-address page even
    // when its amount and ticker fit. Native sentinels remain exempt; for them
    // a pinned ticker is the identity. Overflow also forces the identity page.
    let mut bound_identity_ticker: Option<&[u8]> = None;
    let bound_non_native = token_addr.is_some_and(|addr| !params.native_currency_matches(&addr));

    {
        let [_, r1, r2, foot] = pages.page_mut(p);
        match decision.arm {
            // "unlimited <ticker>" — the approve-all sentinel on a bound token.
            // Never silently truncate the ticker. If message+ticker do not fit on
            // one row, use the second value row; an overlong ticker falls back to
            // an exact token-identity page instead.
            TokenAmountArm::Unlimited { message, ticker } => {
                let ticker_painted = write_unlimited_rows(r1, r2, message, ticker);
                if bound_non_native || !ticker_painted {
                    bound_identity_ticker = Some(ticker);
                }
                write_line(foot, "> next");
                pages.mark_nav(p, 3);
            }
            // Unlimited on an UNKNOWN token: still the loud message (an unbound
            // 2^256-1 used to fall through to "!AMOUNT OVERFLOW" — an alarming
            // banner, no value — exactly when trust is LOWEST), marked
            // "(unverified)" so the missing token identity stays loud (the
            // identity page below still shows the address).
            TokenAmountArm::UnlimitedUnverified { message } => {
                write_line_bytes(r1, message);
                write_line(r2, "(unverified)");
                write_line(foot, "> next");
                pages.mark_nav(p, 3);
            }
            TokenAmountArm::Bound { ticker, .. } => {
                let amount_text = bound_text.expect("bound arm precomputes exact amount text");
                amount_text.paint(r1, r2);
                write_line(foot, "> next");
                pages.mark_nav(p, 3);
                // For a non-native token, independently re-check the metadata's
                // chain as well as its contract before allowing the banner to
                // summarize it. The witness reuses the painted bytes.
                let metadata_chain_bound = !bound_non_native
                    || matches!(
                            (token_addr, erc20),
                            (Some(addr), Some(meta))
                                if meta.chain_id == container.chain_id && meta.contract == addr
                    );
                if metadata_chain_bound {
                    witness = amount_text.witness();
                }
                if bound_non_native {
                    bound_identity_ticker = Some(ticker);
                }
            }
            // Audit M-4: never present a scaled decimal with an assumed scale.
            // Show the RAW integer (no scaling) and label the unknown scale
            // loudly so the user knows the magnitude is uninterpreted.
            TokenAmountArm::UnverifiedRaw => {
                let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, true, "");
                if fit == AmountFit::Full {
                    write_line(foot, "! raw, dec=?");
                } else {
                    raw_fallback = true;
                }
            }
        }
    }

    if raw_fallback {
        write_raw_word_two_pages(pages, p, field.label, &raw)?;
    }

    if let Some(ticker) = bound_identity_ticker {
        append_bound_token_identity(pages, token_addr, params, ticker)?;
    }

    // Audit 2026-06-25 MEDIUM-1: with no Merkle-verified metadata we cannot
    // show decimals/symbol — but the token *identity* is still a signed
    // operand, so the decision carries the resolved address whenever it
    // could not be bound (see `TokenAmountDecision::identity_page` for the
    // full rule). Render it on its own page (resolver-aware) so the
    // contract identity is never omitted from the trusted display; the
    // page-budget gate hard-refuses the verified/known call on overflow.
    if let Some(addr) = decision.identity_page {
        let ap = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, ap, b"Token (UNVERIFIED)");
        let [_, ar1, ar2, ar3] = pages.page_mut(ap);
        write_addr_full_or_name(ar1, ar2, ar3, &addr, container.chain_id, resolver);
    }
    Ok(witness)
}

#[cfg(test)]
mod exact_amount_text_tests {
    use super::*;

    fn word_from_u128(value: u128) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&value.to_be_bytes());
        word
    }

    #[test]
    fn exact_text_selects_zero_six_seven_and_eighteen_fractional_digits() {
        let cases = [
            (2_000_000_000_000_000_000u128, b"2 ETH".as_slice()),
            (1_234_567_000_000_000_000, b"1.234567 ETH".as_slice()),
            (1_234_567_800_000_000_000, b"1.2345678 ETH".as_slice()),
            (
                1_078_608_424_000_534_547,
                b"1.078608424000534547 ETH".as_slice(),
            ),
        ];
        for (raw, expected) in cases {
            let text = ExactAmountText::new(word_from_u128(raw), 18, b"ETH").unwrap();
            assert_eq!(text.text(), expected);
            assert_eq!(text.witness().unwrap().text(), expected);
        }
    }

    #[test]
    fn exact_text_normalizes_zeros_keeps_dust_and_distinguishes_neighbors() {
        let normalized =
            ExactAmountText::new(word_from_u128(1_230_000_000_000_000_000), 18, b"ETH").unwrap();
        assert_eq!(normalized.text(), b"1.23 ETH");

        let dust = ExactAmountText::new(word_from_u128(1), 18, b"ETH").unwrap();
        assert_eq!(dust.text(), b"0.000000000000000001 ETH");

        let a =
            ExactAmountText::new(word_from_u128(1_078_608_424_000_534_547), 18, b"ETH").unwrap();
        let b =
            ExactAmountText::new(word_from_u128(1_078_608_424_000_534_548), 18, b"ETH").unwrap();
        assert_ne!(a.text(), b.text());
    }

    #[test]
    fn exact_text_paints_the_same_complete_bytes_and_refuses_over_capacity() {
        let text =
            ExactAmountText::new(word_from_u128(1_078_608_424_000_534_547), 18, b"ETH").unwrap();
        let mut row1 = [b' '; DISPLAY_COLS];
        let mut row2 = [b' '; DISPLAY_COLS];
        text.paint(&mut row1, &mut row2);
        let mut painted = [0u8; AMOUNT_TEXT_CAPACITY];
        painted[..DISPLAY_COLS].copy_from_slice(&row1);
        painted[DISPLAY_COLS..].copy_from_slice(&row2);
        let painted_len = painted
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |i| i + 1);
        assert_eq!(&painted[..painted_len], text.text());

        assert!(ExactAmountText::new([0xff; 32], 0, b"ETH").is_none());
        assert!(ExactAmountText::new(word_from_u128(1), 36, b"ETH").is_none());
        assert!(ExactAmountText::new(word_from_u128(1), 18, b"E\nTH").is_none());
    }

    #[test]
    fn exact_text_accepts_32_cells_and_refuses_33() {
        // 10^27 has 28 decimal digits; the separator plus `ETH` fills the
        // two 16-cell value rows exactly. One more integer digit must refuse
        // rather than clip the value or its authenticated unit.
        let exact_32 = ExactAmountText::new(word_from_u128(10u128.pow(27)), 0, b"ETH")
            .expect("32-cell exact amount must fit");
        assert_eq!(exact_32.text().len(), AMOUNT_TEXT_CAPACITY);
        assert!(ExactAmountText::new(word_from_u128(10u128.pow(28)), 0, b"ETH").is_none());
    }
}

/// Render `"unlimited <ticker>"` without truncating either component. Used
/// by `render_token_amount` when the descriptor's `threshold` param
/// classifies the on-chain value as the approve-all sentinel.
/// `message` is the descriptor's threshold wording (default `"unlimited"`),
/// already validated as printable and at most one row. Returns `true` only
/// when the complete ticker is on screen. A ticker longer than one row is not
/// partially painted: row 2 points to the exact identity page the caller must
/// append, closing the old prefix-collision (`LONGTOKEN-A`/`LONGTOKEN-B` both
/// displayed as `"unlimited LONGTO"`).
fn write_unlimited_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    message: &[u8],
    ticker: &[u8],
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];

    let combined = message
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(ticker.len()));
    if !ticker.is_empty() && combined.is_some_and(|n| n <= DISPLAY_COLS) {
        row1[..message.len()].copy_from_slice(message);
        row1[message.len()] = b' ';
        row1[message.len() + 1..message.len() + 1 + ticker.len()].copy_from_slice(ticker);
        return true;
    }

    write_line_bytes(row1, message);
    if !ticker.is_empty() && ticker.len() <= DISPLAY_COLS {
        write_line_bytes(row2, ticker);
        true
    } else {
        write_line(row2, "(see token)");
        false
    }
}

/// Append an injective identity sink after a BOUND token's normal ticker could
/// not be painted. ERC-20s use the full EIP-55 contract address, never the
/// resolver's abbreviated name form. Native sentinels have no contract, so
/// their short firmware-pinned ticker is shown byte-exactly instead.
fn append_bound_token_identity(
    pages: &mut Pages,
    token_addr: Option<[u8; 20]>,
    params: &ParamSet<'_>,
    ticker: &[u8],
) -> Result<(), RenderErr> {
    let addr = token_addr.ok_or(RenderErr::Reject("7730 bound token missing"))?;
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    if params.native_currency_matches(&addr) {
        if ticker.is_empty() || ticker.len() > DISPLAY_COLS {
            return Err(RenderErr::Reject("7730 native ticker too long"));
        }
        write_label_row(pages, p, b"Native token");
        let [_, r1, _r2, _r3] = pages.page_mut(p);
        write_line_bytes(r1, ticker);
    } else {
        write_label_row(pages, p, b"Token contract");
        let [_, r1, r2, r3] = pages.page_mut(p);
        write_addr_full(r1, r2, r3, &addr);
    }
    Ok(())
}

fn render_nft_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // The ERC-7730 spec's own fallback for an unresolved NFT is "a raw int
    // token ID". We have no NFT-name DB, so we ALWAYS render that fallback —
    // FAITHFULLY. A token id is an IDENTIFIER, not an amount: it must never go
    // through the amount path, where a large ERC-1155 / structured id would hit
    // AmountFit::Overflow and render "!OVERFLOW" while the tx STILL clear-signs
    // — a verified banner hiding WHICH nft (the exact false-confidence class the
    // `calldata` formatter stays declined for). Small ids render as a decimal;
    // anything that doesn't cleanly fit shows EVERY byte via the shared raw
    // two-page path. Rendered plainly (not under a name-implying gloss), so it
    // satisfies the spec fallback without reopening the original M-7 concern —
    // which was the opposite failure: a bare int dressed up as a resolved name.
    // (review 3.2; deliberately overrides the prior M-7 decline.)
    if !nft_params_are_canonical(params) {
        return Err(RenderErr::Reject("7730 nft collection unbound"));
    }
    let collection = resolve_nft_collection(body, container, params)?;
    let value = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    match read_u64_be_tail(&value) {
        // Fits u64 AND the decimal fits one row (no dropped digit) → "<id>".
        Some(id) if decimal_digits(id) <= DISPLAY_COLS => {
            let [_, r1, _r2, foot] = pages.page_mut(p);
            write_decimal_into(r1, 0, id);
            // ≤16 cols: makes clear it's the raw id, no resolved NFT name.
            write_line(foot, "! raw nft id");
            Ok(())
        }
        // Large / full-uint256 id → show every byte (never a magnitude-hiding
        // overflow marker). Reuses the hardened scalar-raw two-page renderer.
        _ => write_raw_word_two_pages(pages, p, field.label, &value),
    }?;

    // Always show every collection-contract byte even when a friendly name is
    // authenticated. The friendly name occupies only the label row; the three
    // address rows remain complete. Descriptor contractName is eligible only
    // when the collection is the descriptor-bound target. Otherwise require an
    // exact chain+address name capability; wildcard names are insufficient.
    let cp = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    let friendly = if collection == ir.contract && !ir.contract_name.is_empty() {
        Some(ir.contract_name)
    } else if container.chain_id == 0 {
        // Chain id zero is the names DB's wildcard-entry sentinel, not a real
        // exact chain capability. `lookup_exact(0, ..)` would otherwise turn a
        // wildcard record into an NFT semantic identity.
        None
    } else {
        resolver.lookup_exact(container.chain_id, &collection)
    };
    if let Some(name) = friendly {
        write_verified_nft_collection_label(pages.row_mut(cp, 0), name)?;
    } else {
        write_label_row(pages, cp, b"NFT collection");
    }
    let [_, r1, r2, r3] = pages.page_mut(cp);
    write_addr_full(r1, r2, r3, &collection);
    Ok(())
}

fn resolve_nft_collection(
    _body: &[u8],
    container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<[u8; 20], RenderErr> {
    if let Some(path) = params.nft_collection_path {
        if !nft_collection_path_is_current_slice(path) {
            return Err(RenderErr::Reject("7730 bad nft collection path"));
        }
        return Ok(container.target);
    }
    params
        .nft_collection
        .copied()
        .ok_or(RenderErr::Reject("7730 nft collection missing"))
}

/// Paint an authenticated collection name into the page label while keeping
/// all three following rows available for the complete contract. `+` is the
/// established verified-name sentinel; `~` makes any name clipping explicit.
fn write_verified_nft_collection_label(
    row: &mut [u8; DISPLAY_COLS],
    name: &[u8],
) -> Result<(), RenderErr> {
    if name.is_empty() || !name.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(RenderErr::Reject("7730 bad nft collection name"));
    }
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'+';
    row[1] = b' ';
    let room = DISPLAY_COLS - 2;
    if name.len() <= room {
        row[2..2 + name.len()].copy_from_slice(name);
    } else {
        row[2..DISPLAY_COLS - 1].copy_from_slice(&name[..room - 1]);
        row[DISPLAY_COLS - 1] = b'~';
    }
    Ok(())
}

fn render_date(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let secs = match read_u64_be_tail(&bytes) {
        Some(s) => s,
        None => return write_raw_word_two_pages(pages, p, field.label, &bytes),
    };
    let enc = params.date_encoding.unwrap_or(DATE_ENC_TIMESTAMP);
    let [_, r1, r2, foot] = pages.page_mut(p);
    if enc == DATE_ENC_BLOCKHEIGHT {
        // The block id is the signed deadline/expiry, so EVERY digit is
        // security-relevant: a far-future block height must never render as a
        // near one. The previous "block #N" form fed the full u64 `secs`
        // straight into `write_decimal_into`, which silently DROPS low-order
        // digits once the 16-col row fills. With the 7-char "block #" prefix
        // only 9 digits fit, so a >=10-digit height rendered as its top 9
        // digits — e.g. block 12_345_678_901 painted "block #123456789"
        // (~100x understated, yet a plausible near deadline) while the
        // signature committed to the full value. Show the full magnitude
        // instead: the compact "block #N" inline form while every digit fits
        // (the unchanged common case: heights < 1e9), otherwise a label on r1
        // and the full number on its own row r2. An absurd >16-digit value
        // (>= 1e16 — not a real block height on any chain) fails LOUD rather
        // than truncating, mirroring the timestamp branch's `! YEAR >9999`
        // and the `! CHAIN >2^64` guard (audit 2026-06-26 — the
        // magnitude-hiding sibling of the date-year fix 7df062d3).
        const BLOCK_PREFIX: &[u8] = b"block #";
        if BLOCK_PREFIX.len() + decimal_digits(secs) <= DISPLAY_COLS {
            let mut row = [b' '; DISPLAY_COLS];
            let mut pos = 0;
            for &b in BLOCK_PREFIX {
                row[pos] = b;
                pos += 1;
            }
            write_decimal_into(&mut row, pos, secs);
            *r1 = row;
        } else if decimal_digits(secs) <= DISPLAY_COLS {
            write_line(r1, "Block height:");
            let mut row = [b' '; DISPLAY_COLS];
            write_decimal_into(&mut row, 0, secs);
            *r2 = row;
        } else {
            return write_raw_word_two_pages(pages, p, field.label, &bytes);
        }
    } else {
        if !format_iso8601_utc(secs, r1, r2) {
            return write_raw_word_two_pages(pages, p, field.label, &bytes);
        }
    }
    write_line(foot, "> next");
    pages.mark_nav(p, 3);
    Ok(())
}

fn render_duration(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let secs = match read_u64_be_tail(&bytes) {
        Some(s) => s,
        None => return write_raw_word_two_pages(pages, p, field.label, &bytes),
    };
    let [_, r1, _r2, foot] = pages.page_mut(p);
    if !format_duration(secs, r1) {
        return write_raw_word_two_pages(pages, p, field.label, &bytes);
    }
    write_line(foot, "> next");
    pages.mark_nav(p, 3);
    Ok(())
}

fn render_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let resolved = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => canonical_address_word(b)?,
        Resolved::Container(idx) => container_addr(container, idx)?,
    };
    // `senderAddress` is an exact descriptor-authenticated sentinel list, not
    // an address-range heuristic. Resolve and canonicalize the signed word
    // first; only a complete member match may substitute the independently
    // derived UserOperation sender. A generic renderer without that binding
    // fails closed instead of painting the sentinel as a beneficiary.
    let substituted_sender = params.sender_address_matches(&resolved);
    let addr = if substituted_sender {
        container
            .from
            .ok_or(RenderErr::Reject("7730 sender unbound"))?
    } else {
        resolved
    };
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    // The authenticated name DB currently carries no source provenance or
    // entity type. When a descriptor declares either restriction we cannot
    // prove a resolved label satisfies it, so retain WYSIWYS by showing the
    // complete address instead of substituting a possibly-disallowed name.
    if substituted_sender || params.addr_types.is_some() || params.addr_sources.is_some() {
        write_addr_full(r1, r2, r3, &addr);
    } else {
        write_addr_full_or_name(r1, r2, r3, &addr, container.chain_id, resolver);
    }
    Ok(())
}

/// Render a constant-annotation field — a path-less `{value,label}` whose
/// `value` is a fixed descriptor-pinned string carried in the IR pool. Not bound
/// to calldata, so there is no path to resolve: it shows the same text for
/// every transaction (e.g. the ERC-4626 vault share/asset tickers). The
/// string is Merkle-pinned, so it is no more trusted than the field label
/// or intent banner.
fn render_const(field: &FieldEntry<'_>, pages: &mut Pages, value: &[u8]) -> Result<(), RenderErr> {
    // A trailing space is indistinguishable from display padding unless a
    // length marker is shown. Constants are descriptor annotations rather than
    // signed payload, so keep their encoding canonical and reject that
    // ambiguity. Long values span as many complete pages as needed; never drop
    // bytes after the old three-row/48-byte boundary.
    if value.is_empty()
        || value.last() == Some(&b' ')
        || !value.iter().all(|&b| (0x20..0x7f).contains(&b))
    {
        return Err(RenderErr::Reject("7730 bad const value"));
    }
    for page_chunk in value.chunks(3 * DISPLAY_COLS) {
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, p, field.label);
        let [_, r1, r2, r3] = pages.page_mut(p);
        let rows: [&mut [u8; DISPLAY_COLS]; 3] = [r1, r2, r3];
        let mut chunks = page_chunk.chunks(DISPLAY_COLS);
        for row in rows {
            match chunks.next() {
                Some(c) => write_line_bytes(row, c),
                None => write_line_bytes(row, b""),
            }
        }
    }
    Ok(())
}

/// True iff the field's compiled path is STRUCTURALLY a render-every-element
/// array path: `RootStructured` then `FieldIdx*` then exactly `ArrayAll`.
///
/// Validates the opcode STRUCTURE, not just `prog.last() == 0x24` — a scalar
/// field's terminal `FieldIdx` whose 2-byte arg's low byte is `0x24`
/// (`PathOp::ArrayAll`) must NOT misroute to `render_array` (it would still
/// reject there, but it would needlessly refuse an otherwise clear-signable
/// scalar field).
pub fn path_ends_with_array_all(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<bool, RenderErr> {
    if path_off == 0 {
        return Ok(false);
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Ok(false);
    }
    let mut p = 1usize;
    while let Some(&op) = prog.get(p) {
        if op == PathOp::FieldIdx as u8 {
            if p + 3 > prog.len() {
                return Ok(false);
            }
            p += 3;
        } else if op == PathOp::FollowOffset as u8 {
            // Multi-dynamic array marker (`FieldIdx* FollowOffset ArrayAll`).
            p += 1;
        } else if op == PathOp::ArrayAll as u8 {
            return Ok(p + 1 == prog.len()); // ArrayAll must be the final op
        } else {
            return Ok(false);
        }
    }
    Ok(false)
}

/// Detect the retired multi-dynamic array marker (`FollowOffset` before the
/// terminal `ArrayAll`). It is parsed structurally so the format preflight and
/// renderer can hard-refuse it; no relaxed production resolver remains.
fn array_all_is_multi(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<bool, RenderErr> {
    if path_off == 0 {
        return Ok(false);
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Ok(false);
    }

    // Decode opcodes at their structural boundaries. A raw byte search is
    // unsafe here because the two-byte operand of FieldIdx is attacker-chosen
    // authenticated IR and may itself contain 0x25 (FollowOffset), which would
    // otherwise route a sole-array path through the relaxed multi-tail checks.
    let mut p = 1usize;
    let mut saw_follow = false;
    while let Some(&raw) = prog.get(p) {
        let op = PathOp::try_from(raw).map_err(|_| RenderErr::Reject("7730 bad array path op"))?;
        match op {
            PathOp::FieldIdx => {
                if p + 3 > prog.len() {
                    return Err(RenderErr::Reject("7730 truncated array field"));
                }
                p += 3;
            }
            PathOp::FollowOffset => {
                if saw_follow {
                    return Err(RenderErr::Reject("7730 duplicate array follow"));
                }
                saw_follow = true;
                p += 1;
            }
            PathOp::ArrayAll => {
                if p + 1 != prog.len() {
                    return Err(RenderErr::Reject("7730 trailing array path"));
                }
                return Ok(saw_follow);
            }
            _ => return Err(RenderErr::Reject("7730 bad array path shape")),
        }
    }
    Err(RenderErr::Reject("7730 missing array-all"))
}

/// Scan a compiled structured path's opcodes → `(needs_full_body, is_dynamic_leaf)`.
///
/// * `needs_full_body` — the path descends through a `FollowOffset` (a dynamic
///   arg / dynamic tuple), so it must resolve against the FULL calldata body,
///   not the head-bounded slice.
/// * `is_dynamic_leaf` — the leaf itself is a dynamic `bytes`/`string` blob (the
///   program ends on `FollowOffset`), routed to [`render_dynamic_bytes`].
///
/// Any non-`FieldIdx`/`FollowOffset` op (e.g. `ArrayAll`) → `(false,false)`:
/// arrays route via [`path_ends_with_array_all`], scalars via the head path.
fn scan_path_ops(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<(bool, bool), RenderErr> {
    if path_off == 0 {
        return Ok((false, false));
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Ok((false, false));
    }
    let mut p = 1usize;
    let mut has_follow = false;
    let mut ends_on_follow = false;
    while let Some(&op) = prog.get(p) {
        if op == PathOp::FieldIdx as u8 {
            if p + 3 > prog.len() {
                return Ok((false, false));
            }
            p += 3;
            ends_on_follow = false;
        } else if op == PathOp::FollowOffset as u8 {
            has_follow = true;
            ends_on_follow = true;
            p += 1;
        } else {
            return Ok((false, false));
        }
    }
    Ok((has_follow, ends_on_follow))
}

/// The path descends a dynamic offset → resolve against the full calldata body.
pub(crate) fn path_needs_full_body(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<bool, RenderErr> {
    Ok(scan_path_ops(ir, path_off)?.0)
}

/// The leaf is a dynamic `bytes`/`string` blob (C1) → [`render_dynamic_bytes`].
pub(crate) fn path_is_dynamic_leaf(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<bool, RenderErr> {
    Ok(scan_path_ops(ir, path_off)?.1)
}

/// A `tokenAmount`'s `tokenPath` descends a `FollowOffset` (dynamic tuple /
/// `bytes` / `address[]`) → the token id lives in the calldata tail, so the
/// field must resolve against the FULL body even when its OWN amount path is
/// static-head (e.g. `swapExactTokensForTokens`: static `amountIn`, dynamic
/// `path.[0]` token id). Parses ops properly (a `FieldIdx` slot byte can equal
/// `FollowOffset`'s opcode, so a raw byte scan would false-positive). Any
/// extraction op (`ArrayIdx`/`ArrayLast`/`ArraySlice`) is emitted only AFTER a
/// `FollowOffset`, so scanning to the first follow suffices.
pub(crate) fn token_path_needs_full_body(params: &ParamSet<'_>) -> bool {
    let Some(tp) = params.token_path else {
        return false;
    };
    if tp.first() != Some(&(PathOp::RootStructured as u8)) {
        return false;
    }
    let mut p = 1usize;
    while let Some(&op) = tp.get(p) {
        match PathOp::try_from(op) {
            Ok(PathOp::FieldIdx) => {
                if p + 3 > tp.len() {
                    return false;
                }
                p += 3;
            }
            Ok(PathOp::FollowOffset) => return true,
            // A static-head tokenPath (or a malformed one) resolves head-bounded;
            // if it turns out to need the tail it declines to the raw fallback.
            _ => return false,
        }
    }
    false
}

/// Enforce that a structured path's first ABI offset/static word comes from the
/// format-declared top-level head. Dynamic renderers need the full calldata body
/// after following that word; without this independent clamp a malicious IR
/// could put its first `FieldIdx` in the tail and reinterpret attacker-chosen
/// bytes there as an offset.
fn validate_root_program_static_head(prog: &[u8], static_head_words: u16) -> Result<(), RenderErr> {
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Ok(());
    }
    let mut p = 1usize;
    let mut slot = 0usize;
    let mut saw_field = false;
    while p < prog.len() {
        let op = PathOp::try_from(prog[p]).map_err(|_| RenderErr::Reject("7730 bad path op"))?;
        match op {
            PathOp::FieldIdx => {
                let arg = prog
                    .get(p + 1..p + 3)
                    .ok_or(RenderErr::Reject("7730 truncated field idx"))?;
                slot = slot
                    .checked_add(u16::from_be_bytes([arg[0], arg[1]]) as usize)
                    .ok_or(RenderErr::Reject("7730 root slot overflow"))?;
                saw_field = true;
                p += 3;
            }
            // Once an offset is followed, later indices are relative to the
            // nested region and need a different bound. This guard is solely
            // for the top-level, signature-fixed offset word.
            PathOp::FollowOffset => break,
            PathOp::ArrayAll | PathOp::ArrayIdx | PathOp::ArrayLast | PathOp::ArraySlice => break,
            _ => return Err(RenderErr::Reject("7730 bad structured root")),
        }
    }
    if !saw_field || slot >= static_head_words as usize {
        return Err(RenderErr::Reject("7730 root outside static head"));
    }
    Ok(())
}

pub(crate) fn validate_path_static_head(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    static_head_words: u16,
) -> Result<(), RenderErr> {
    if path_off == 0 {
        return Ok(()); // canonical const validation owns the no-path case
    }
    let prog = ir
        .path_bytes(path_off)
        .map_err(|_| RenderErr::Reject("7730 bad path"))?;
    validate_root_program_static_head(prog, static_head_words)
}

pub(crate) fn validate_token_path_static_head(
    params: &ParamSet<'_>,
    static_head_words: u16,
) -> Result<(), RenderErr> {
    if let Some(prog) = params.token_path {
        validate_root_program_static_head(prog, static_head_words)?;
    }
    if let Some(prog) = params.nft_collection_path {
        if !nft_collection_path_is_current_slice(prog) {
            return Err(RenderErr::Reject("7730 bad nft collection path"));
        }
        validate_root_program_static_head(prog, static_head_words)?;
    }
    Ok(())
}

/// Bind every exact dynamic-tail reference in one format to a single
/// top-level offset-word slot.
fn bind_sole_dynamic_slot(seen: &mut Option<usize>, slot: usize) -> Result<(), RenderErr> {
    match *seen {
        Some(previous) if previous != slot => Err(RenderErr::Reject("7730 multiple dynamic args")),
        Some(_) => Ok(()),
        None => {
            *seen = Some(slot);
            Ok(())
        }
    }
}

/// Recover the sole format-level topology marker from its canonical field-zero
/// location. Deep IR validation owns the primary placement rule; this local
/// scan keeps the publication boundary fail-closed if a malformed in-memory IR
/// view reaches it.
fn authenticated_dynamic_tail_topology(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
) -> Result<Option<TailTopology>, RenderErr> {
    let mut topology = None;
    for (ordinal, field_result) in format.fields().enumerate() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        if let Some(candidate) = params.dynamic_tail_topology {
            if ordinal != 0 || topology.is_some() || ir.context_kind != ContextKind::Contract {
                return Err(RenderErr::Reject("7730 topology placement"));
            }
            candidate.validate_static_head(format.static_head_words)?;
            topology = Some(candidate);
        }
    }
    Ok(topology)
}

/// Bind one field/token reference to the authenticated interval of matching
/// kind and record that the format actually consumes the topology record.
fn consume_partition_record(
    consumed: &mut u8,
    partition: &TailPartition,
    slot: usize,
    kind: TailKind,
) -> Result<TailInterval, RenderErr> {
    let (ordinal, interval) = partition.find(slot, kind)?;
    mark_partition_record(consumed, ordinal)?;
    Ok(interval)
}

fn mark_partition_record(consumed: &mut u8, ordinal: usize) -> Result<(), RenderErr> {
    let bit = 1u8
        .checked_shl(u32::try_from(ordinal).map_err(|_| RenderErr::Reject("7730 topology bit"))?)
        .ok_or(RenderErr::Reject("7730 topology bit"))?;
    *consumed |= bit;
    Ok(())
}

fn require_all_partition_records_consumed(
    consumed: u8,
    partition: &TailPartition,
) -> Result<(), RenderErr> {
    let count =
        u32::try_from(partition.len()).map_err(|_| RenderErr::Reject("7730 topology bit"))?;
    let expected = 1u8
        .checked_shl(count)
        .ok_or(RenderErr::Reject("7730 topology bit"))?
        .wrapping_sub(1);
    if consumed != expected {
        return Err(RenderErr::Reject("7730 topology unconsumed tail"));
    }
    Ok(())
}

/// Parse the exact sole-array program emitted by dbgen:
/// `RootStructured FieldIdx(slot) ArrayAll`.
fn sole_array_slot(ir: &Erc7730Ir<'_>, path_off: u16) -> Result<usize, RenderErr> {
    let prog = ir
        .path_bytes(path_off)
        .map_err(|_| RenderErr::Reject("7730 bad array path"))?;
    if prog.len() != 5
        || prog[0] != PathOp::RootStructured as u8
        || prog[1] != PathOp::FieldIdx as u8
        || prog[4] != PathOp::ArrayAll as u8
    {
        return Err(RenderErr::Reject("7730 noncanonical array path"));
    }
    Ok(u16::from_be_bytes([prog[2], prog[3]]) as usize)
}

fn validate_dynamic_leaf_params(
    field: &FieldEntry<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    if !matches!(
        params.dynamic_kind,
        Some(DYNAMIC_KIND_STRING) | Some(DYNAMIC_KIND_BYTES)
    ) {
        return Err(RenderErr::Reject("7730 dynamic type unbound"));
    }
    if params.exact_empty_bytes
        && (field.format_op != FormatOp::Raw as u8
            || field.label != b"Callback"
            || params.visibility != crate::ir::Visibility::Always
            || params.dynamic_kind != Some(DYNAMIC_KIND_BYTES))
    {
        return Err(RenderErr::Reject("7730 bad exact-empty field"));
    }
    Ok(())
}

/// Validate a top-level C1 `bytes`/`string` leaf as the sole exact tail.
fn validate_c1_dynamic_leaf<'a>(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    params: &ParamSet<'_>,
    full_body: &'a [u8],
    static_head_words: u16,
) -> Result<(usize, &'a [u8]), RenderErr> {
    validate_dynamic_leaf_params(field, params)?;
    let prog = ir
        .path_bytes(field.path_off)
        .map_err(|_| RenderErr::Reject("7730 bad dynamic path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Err(RenderErr::Reject("7730 dyn bad root"));
    }
    let slot = crate::render::resolve::c1_dynamic_slot(&prog[1..])?;
    if slot >= static_head_words as usize {
        return Err(RenderErr::Reject("7730 dynamic slot out of head"));
    }
    let head_end = (static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 dynamic head ovf"))?;
    let leaf = crate::render::resolve::resolve_structured(&prog[1..], full_body)?;
    let off = match leaf {
        crate::render::resolve::Leaf::Dynamic(off) => off,
        crate::render::resolve::Leaf::Word(_) => {
            return Err(RenderErr::Reject("7730 dyn leaf is word"))
        }
    };
    let data = if params.exact_empty_bytes {
        crate::render::resolve::read_exact_empty_dynamic_whole_tail(full_body, off, head_end)?
    } else {
        crate::render::resolve::read_dynamic_whole_tail(full_body, off, head_end)?
    };
    Ok((slot, data))
}

/// Validate one direct dynamic blob against an already-proven multi-tail
/// partition. The path must identify the same authenticated head slot and the
/// EVM-resolved object start must equal the partition boundary.
fn validate_partitioned_dynamic_leaf<'a>(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    params: &ParamSet<'_>,
    full_body: &'a [u8],
    static_head_words: u16,
    partition: &TailPartition,
    consumed: &mut u8,
) -> Result<(usize, &'a [u8]), RenderErr> {
    validate_dynamic_leaf_params(field, params)?;
    let prog = ir
        .path_bytes(field.path_off)
        .map_err(|_| RenderErr::Reject("7730 bad dynamic path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Err(RenderErr::Reject("7730 dyn bad root"));
    }
    let slot = crate::render::resolve::c1_dynamic_slot(&prog[1..])?;
    if slot >= usize::from(static_head_words) {
        return Err(RenderErr::Reject("7730 dynamic slot out of head"));
    }
    let interval = consume_partition_record(consumed, partition, slot, TailKind::Blob)?;
    let off = match crate::render::resolve::resolve_structured(&prog[1..], full_body)? {
        crate::render::resolve::Leaf::Dynamic(off) => off,
        crate::render::resolve::Leaf::Word(_) => {
            return Err(RenderErr::Reject("7730 dyn leaf is word"));
        }
    };
    if off != interval.object_start {
        return Err(RenderErr::Reject("7730 dynamic partition mismatch"));
    }
    let data = interval.data(full_body)?;
    if params.exact_empty_bytes && !data.is_empty() {
        return Err(RenderErr::Reject("7730 res dynamic not empty"));
    }
    Ok((slot, data))
}

/// Format-level canonical ABI preflight for contract calldata.
///
/// This runs before visibility and before any pages are painted, so hidden
/// fields cannot bypass framing validation. Today's IR can prove exact layout
/// for all-static calls, legacy sole top-level dynamic tails, an authenticated
/// two-to-four-object top-level partition, and the exact deployment-scoped
/// Router02 packed-path C2 mode:
///
/// * all-static: calldata body length equals the authenticated head length;
/// * sole dynamic: offset equals head end and the padded object consumes the
///   complete body;
/// * bounded multi-tail: authenticated slots/kinds exactly tile the bytes after
///   the head, and every topology record is consumed by a field/token path;
/// * every dynamic reference names the same head slot;
/// * generic C2 dynamic-tuple descent and the retired relaxed multi-array marker
///   reject;
/// * Router02 C2 requires the exact chain, target, selector, five field roles,
///   guards, canonical recipient, whole path tail, and hop cap.
///
/// Dbgen enforces the corresponding signature-level restrictions. This belt
/// independently covers hidden paths and authenticated-but-malformed IR.
pub(crate) fn validate_contract_calldata_framing(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    full_body: &[u8],
    container: &ContractContainerCtx,
) -> Result<ContractCalldataMode, RenderErr> {
    let head_end = (format.static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 head overflow"))?;
    if full_body.len() < head_end {
        return Err(RenderErr::Reject("7730 short head"));
    }
    let topology = authenticated_dynamic_tail_topology(ir, format)?;
    let partition = match topology {
        Some(topology) => Some(validate_exact_partition(
            &topology,
            full_body,
            format.static_head_words,
        )?),
        None => None,
    };

    // The new packed-path opcode is the sole minting point for C2 authority.
    // Authenticate the exact deployment/selector/five-field shape, then parse
    // the entire Router02 body (including path cap, padding, exact end and
    // recipient canonicality) before guards or any reassuring page can run.
    let mut packed_fields = 0u8;
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        if field.format_op == FormatOp::UniswapV3Path as u8 {
            packed_fields = packed_fields
                .checked_add(1)
                .ok_or(RenderErr::Reject("7730 v3 field count"))?;
        }
    }
    if packed_fields != 0 {
        if packed_fields != 1 || partition.is_some() {
            return Err(RenderErr::Reject("7730 v3 field count"));
        }
        let direction = validate_uniswap_v3_runtime_format(ir, format, container)?;
        parse_router02_body(full_body)?;
        return Ok(ContractCalldataMode::UniswapV3Path(direction));
    }

    let mut dynamic_slot: Option<usize> = None;
    let mut consumed_partition_records = 0u8;
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        validate_path_static_head(ir, field.path_off, format.static_head_words)?;
        validate_token_path_static_head(&params, format.static_head_words)?;
        if params.exact_empty_bytes {
            let (has_follow, ends_on_follow) = scan_path_ops(ir, field.path_off)?;
            if !has_follow || !ends_on_follow {
                return Err(RenderErr::Reject("7730 bad exact-empty path"));
            }
        }

        if path_ends_with_array_all(ir, field.path_off)? {
            if array_all_is_multi(ir, field.path_off)? {
                return Err(RenderErr::Reject("7730 multi-array framing"));
            }
            let slot = sole_array_slot(ir, field.path_off)?;
            // Exact offset/head/end checks run even for `visible:never`.
            let (elems_start, count) = if let Some(partition) = &partition {
                let interval = consume_partition_record(
                    &mut consumed_partition_records,
                    partition,
                    slot,
                    TailKind::StaticWordArray,
                )?;
                let count = usize::try_from(interval.count)
                    .map_err(|_| RenderErr::Reject("7730 arr count"))?;
                if count > MAX_ARRAY_RENDER {
                    return Err(RenderErr::Reject("7730 arr over cap"));
                }
                (interval.data_start, count)
            } else {
                bind_sole_dynamic_slot(&mut dynamic_slot, slot)?;
                resolve_array(&field, ir, full_body, format.static_head_words)?
            };
            for index in 0..count {
                let word = array_element_word(full_body, elems_start, index)?;
                require_integer_word_canonical(&params, word)?;
            }
        } else {
            require_integer_path_canonical(ir, &field, full_body, &params)?;
            let (has_follow, ends_on_follow) = scan_path_ops(ir, field.path_off)?;
            if has_follow {
                if !ends_on_follow {
                    return Err(RenderErr::Reject("7730 C2 framing unsupported"));
                }
                if let Some(partition) = &partition {
                    let _ = validate_partitioned_dynamic_leaf(
                        ir,
                        &field,
                        &params,
                        full_body,
                        format.static_head_words,
                        partition,
                        &mut consumed_partition_records,
                    )?;
                } else {
                    let (slot, _data) = validate_c1_dynamic_leaf(
                        ir,
                        &field,
                        &params,
                        full_body,
                        format.static_head_words,
                    )?;
                    bind_sole_dynamic_slot(&mut dynamic_slot, slot)?;
                }
            }
        }

        if token_path_needs_full_body(&params) {
            let token_path = params
                .token_path
                .ok_or(RenderErr::Reject("7730 missing token path"))?;
            if token_path.first() != Some(&(PathOp::RootStructured as u8)) {
                return Err(RenderErr::Reject("7730 bad token path root"));
            }
            if let Some(partition) = &partition {
                let (_slot, ordinal) = crate::render::resolve::validate_partitioned_token_tail(
                    &token_path[1..],
                    full_body,
                    format.static_head_words,
                    partition,
                )?;
                mark_partition_record(&mut consumed_partition_records, ordinal)?;
            } else {
                let slot = crate::render::resolve::validate_canonical_token_tail(
                    &token_path[1..],
                    full_body,
                    format.static_head_words,
                )?;
                bind_sole_dynamic_slot(&mut dynamic_slot, slot)?;
            }
        }
    }

    if let Some(partition) = partition {
        require_all_partition_records_consumed(consumed_partition_records, &partition)?;
        return Ok(ContractCalldataMode::MultiTail(partition));
    }
    if dynamic_slot.is_none() && full_body.len() != head_end {
        return Err(RenderErr::Reject("7730 static calldata trailing"));
    }
    Ok(ContractCalldataMode::Standard)
}

/// Evaluate every authenticated scalar word guard before an intent banner or
/// field page is published. Deep IR validation restricts contract guards to
/// static scalars and EIP-712 guards to one top-level encodeData word; these
/// local checks retain that fail-closed contract if a faulted in-memory view
/// reaches either renderer.
pub(crate) fn validate_contract_word_guards(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    head_body: &[u8],
    full_body: &[u8],
    mode: ContractCalldataMode,
    container: &ContractContainerCtx,
) -> Result<(), RenderErr> {
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        let Some(guard) = params.word_guard else {
            continue;
        };
        if ir.context_kind == crate::ir::ContextKind::Eip712 {
            let path = ir
                .path_bytes(field.path_off)
                .map_err(|_| RenderErr::Reject("7730 bad eip712 guard path"))?;
            crate::ir::validate_eip712_word_guard_path(path)
                .map_err(|_| RenderErr::Reject("7730 bad eip712 guard path"))?;
        }
        if params.visibility != crate::ir::Visibility::Always {
            return Err(RenderErr::Reject("7730 guarded field hidden"));
        }
        validate_path_static_head(ir, field.path_off, format.static_head_words)?;
        let field_body = if path_needs_full_body(ir, field.path_off)? {
            match mode {
                ContractCalldataMode::UniswapV3Path(_)
                    if router02_c2_scalar_field(ir, &field, &params)? =>
                {
                    full_body
                }
                _ => return Err(RenderErr::Reject("7730 guarded C2 unsupported")),
            }
        } else {
            head_body
        };
        let actual = match resolve_path(ir, field.path_off, field_body)? {
            Resolved::Slot32(word) => *word,
            Resolved::Container(container_field::VALUE) => {
                if params.terminal_kind != Some(TerminalKind::Unsigned)
                    || params.integer_width_bytes != Some(32)
                {
                    return Err(RenderErr::Reject("7730 bad guarded value"));
                }
                container_u256(container, container_field::VALUE)?
            }
            Resolved::Container(_) => return Err(RenderErr::Reject("7730 bad guarded container")),
        };
        match params.terminal_kind {
            Some(TerminalKind::Unsigned) => require_integer_word_canonical(&params, &actual)?,
            Some(TerminalKind::Address) => {
                canonical_address_word(&actual)?;
            }
            _ => return Err(RenderErr::Reject("7730 bad guarded kind")),
        }
        if !guard.accepts(&actual) {
            return Err(RenderErr::Reject("7730 word guard failed"));
        }
    }
    Ok(())
}

/// Resolve a direct dynamic blob through the authority minted by the complete
/// format preflight. Sole-tail and partitioned modes share the same path walk;
/// only the authenticated object boundary differs.
pub(crate) fn resolve_dynamic_geometry<'a>(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    body: &'a [u8],
    static_head_words: u16,
    mode: ContractCalldataMode,
) -> Result<crate::render::resolve::CanonicalDynamicTail<'a>, RenderErr> {
    use crate::render::resolve::{canonical_dynamic_whole_tail, resolve_structured, Leaf};
    if path_off == 0 {
        return Err(RenderErr::Reject("7730 dyn no path"));
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Err(RenderErr::Reject("7730 dyn bad root"));
    }
    let slot = crate::render::resolve::c1_dynamic_slot(&prog[1..])?;
    if slot >= static_head_words as usize {
        return Err(RenderErr::Reject("7730 dynamic slot out of head"));
    }
    let head_end = (static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 dynamic head ovf"))?;
    let object_start = match resolve_structured(&prog[1..], body)? {
        Leaf::Dynamic(offset) => offset,
        Leaf::Word(_) => return Err(RenderErr::Reject("7730 dyn leaf is word")),
    };
    match mode {
        ContractCalldataMode::Standard => {
            canonical_dynamic_whole_tail(body, object_start, head_end)
        }
        ContractCalldataMode::MultiTail(partition) => {
            if partition.head_end() != head_end || partition.body_end() != body.len() {
                return Err(RenderErr::Reject("7730 dynamic partition bounds"));
            }
            let (_, interval) = partition.find(slot, TailKind::Blob)?;
            if object_start != interval.object_start {
                return Err(RenderErr::Reject("7730 dynamic partition mismatch"));
            }
            let data = interval.data(body)?;
            Ok(crate::render::resolve::CanonicalDynamicTail {
                length_word_start: interval.object_start,
                data_start: interval.data_start,
                data_end: interval.data_end,
                padded_end: interval.object_end,
                data,
            })
        }
        ContractCalldataMode::UniswapV3Path(_) => {
            Err(RenderErr::Reject("7730 dynamic mode mismatch"))
        }
    }
}

fn resolve_dynamic<'a>(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    body: &'a [u8],
    static_head_words: u16,
    mode: ContractCalldataMode,
    exact_empty: bool,
) -> Result<&'a [u8], RenderErr> {
    let geometry = resolve_dynamic_geometry(ir, path_off, body, static_head_words, mode)?;
    if exact_empty && !geometry.data.is_empty() {
        return Err(RenderErr::Reject("7730 res dynamic not empty"));
    }
    Ok(geometry.data)
}

/// Maximum exact preimage admitted for one authenticated EIP-712 string-hash
/// member. Four 32-byte pages keep both display and witness consumption
/// bounded; longer strings refuse rather than clip or substitute their hash.
pub(super) const EIP712_STRING_PREIMAGE_MAX: usize = 128;
const EIP712_STRING_BYTES_PER_PAGE: usize = 2 * DISPLAY_COLS;

/// Resolve the exact direct EIP-712 member word selected by authenticated IR.
/// This deliberately accepts only `RootStructured / FieldIdx(slot)`: an
/// EIP-712 string member carries its Keccak commitment in the static member
/// word and has no ABI tail or `FollowOffset` to resolve.
pub(super) fn resolve_eip712_string_hash_word<'body>(
    ir: &Erc7730Ir<'_>,
    field: &FieldEntry<'_>,
    body: &'body [u8],
    static_head_words: u16,
) -> Result<&'body [u8; 32], RenderErr> {
    if field.format_op != FormatOp::Raw as u8 || field.path_off == 0 {
        return Err(RenderErr::Reject("7730 string hash path shape"));
    }
    let path = ir
        .path_bytes(field.path_off)
        .map_err(|_| RenderErr::Reject("7730 string hash path"))?;
    if path.len() != 4
        || path[0] != PathOp::RootStructured as u8
        || path[1] != PathOp::FieldIdx as u8
    {
        return Err(RenderErr::Reject("7730 string hash path shape"));
    }
    let slot = u16::from_be_bytes([path[2], path[3]]);
    if slot >= static_head_words {
        return Err(RenderErr::Reject("7730 string hash slot"));
    }
    let start = usize::from(slot)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 string hash slot overflow"))?;
    let end = start
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 string hash slot overflow"))?;
    body.get(start..end)
        .ok_or(RenderErr::Reject("7730 string hash word missing"))?
        .try_into()
        .map_err(|_| RenderErr::Reject("7730 string hash word missing"))
}

/// Paint a previously hash-authenticated EIP-712 string preimage exactly.
/// Validation and the complete page reservation happen before the first page
/// mutation. Every accepted byte occupies its deterministic display cell, and
/// each page repeats the authenticated label plus `part/total` and exact byte
/// length, so trailing spaces cannot collapse into display padding.
pub(super) fn render_eip712_string_preimage(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    preimage: &[u8],
) -> Result<(), RenderErr> {
    if field.format_op != FormatOp::Raw as u8 {
        return Err(RenderErr::Reject("7730 string formatter mismatch"));
    }
    if preimage.len() > EIP712_STRING_PREIMAGE_MAX
        || !preimage.iter().all(|byte| (0x20..0x7f).contains(byte))
    {
        return Err(RenderErr::Reject("7730 string not displayable"));
    }
    let page_count = if preimage.is_empty() {
        1
    } else {
        preimage.len().div_ceil(EIP712_STRING_BYTES_PER_PAGE)
    };
    if page_count > MAX_PAGES.saturating_sub(pages.len) {
        return Err(RenderErr::PageBudget);
    }

    for part in 0..page_count {
        // This cannot fail after the complete reservation check above; retain
        // the normal hard-refusal mapping as a local defense if Pages changes.
        let page = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, page, field.label);
        if preimage.is_empty() {
            write_line_bytes(pages.row_mut(page, 1), b"<empty>");
        } else {
            let start = part * EIP712_STRING_BYTES_PER_PAGE;
            let end = (start + EIP712_STRING_BYTES_PER_PAGE).min(preimage.len());
            let chunk = &preimage[start..end];
            let first_end = chunk.len().min(DISPLAY_COLS);
            write_line_bytes(pages.row_mut(page, 1), &chunk[..first_end]);
            if chunk.len() > DISPLAY_COLS {
                write_line_bytes(pages.row_mut(page, 2), &chunk[DISPLAY_COLS..]);
            }
        }
        write_eip712_string_footer(pages.row_mut(page, 3), part + 1, page_count, preimage.len());
    }
    Ok(())
}

fn append_small_decimal(row: &mut [u8; DISPLAY_COLS], mut position: usize, value: usize) -> usize {
    let mut digits = [0u8; 3];
    let mut remaining = value;
    let mut count = 0usize;
    loop {
        digits[count] = b'0' + (remaining % 10) as u8;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        row[position] = digits[index];
        position += 1;
    }
    position
}

fn write_eip712_string_footer(
    row: &mut [u8; DISPLAY_COLS],
    part: usize,
    total: usize,
    byte_len: usize,
) {
    *row = [b' '; DISPLAY_COLS];
    // Under the fixed caps the longest footer is `4/4 128 bytes` (13 cells).
    let mut position = append_small_decimal(row, 0, part);
    row[position] = b'/';
    position += 1;
    position = append_small_decimal(row, position, total);
    row[position] = b' ';
    position += 1;
    position = append_small_decimal(row, position, byte_len);
    row[position..position + 6].copy_from_slice(b" bytes");
}

/// C1: render a dynamic ABI `string` field only when dbgen authenticated its
/// type and every byte can be shown injectively. Arbitrary `bytes` are semantic
/// blobs, not text; accepting a length + prefix let an attacker change every
/// byte after the preview without changing the clear-sign pages, so they now
/// decline. The final row carries the exact byte length, making trailing spaces
/// distinguishable from display padding (`"alice"` != `"alice "`).
const DYN_TEXT_MAX: usize = 2 * DISPLAY_COLS;
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn render_dynamic_bytes(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    render_dynamic_bytes_with_mode(
        field,
        pages,
        ir,
        full_body,
        static_head_words,
        ContractCalldataMode::Standard,
        erc20,
        resolver,
        params,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_dynamic_bytes_with_mode(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
    mode: ContractCalldataMode,
    _erc20: Option<&Erc20Metadata<'_>>,
    _resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    if field.format_op != FormatOp::Raw as u8 {
        return Err(RenderErr::Reject("7730 dynamic formatter mismatch"));
    }
    let exact_empty = match params.dynamic_kind {
        Some(DYNAMIC_KIND_STRING) if !params.exact_empty_bytes => false,
        Some(DYNAMIC_KIND_BYTES) if params.exact_empty_bytes => true,
        Some(DYNAMIC_KIND_BYTES) => return Err(RenderErr::Reject("7730 opaque bytes")),
        _ => return Err(RenderErr::Reject("7730 dynamic type unbound")),
    };
    if exact_empty {
        if field.label != b"Callback" || !exact_empty_bytes_params_are_canonical(params) {
            return Err(RenderErr::Reject("7730 dynamic formatter mismatch"));
        }
    } else if !dynamic_string_params_are_canonical(params) {
        return Err(RenderErr::Reject("7730 dynamic formatter mismatch"));
    }
    let data = resolve_dynamic(
        ir,
        field.path_off,
        full_body,
        static_head_words,
        mode,
        exact_empty,
    )?;
    if exact_empty {
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, p, b"Callback");
        write_line(pages.row_mut(p, 1), "none");
        return Ok(());
    }
    if data.len() > DYN_TEXT_MAX || !data.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(RenderErr::Reject("7730 string not displayable"));
    }
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, foot] = pages.page_mut(p);
    let rows: [&mut [u8; DISPLAY_COLS]; 2] = [r1, r2];
    for (i, row) in rows.into_iter().enumerate() {
        let start = i * DISPLAY_COLS;
        if start >= data.len() {
            break;
        }
        let end = (start + DISPLAY_COLS).min(data.len());
        write_line_bytes(row, &data[start..end]);
    }
    write_bytes_len_row(foot, data.len());
    Ok(())
}

/// Write `"<n> bytes"` into a 16-col row.
fn write_bytes_len_row(row: &mut [u8; DISPLAY_COLS], n: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 20];
    let mut m = n;
    let mut dlen = 0;
    if m == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while m > 0 && dlen < digits.len() {
            digits[dlen] = b'0' + (m % 10) as u8;
            m /= 10;
            dlen += 1;
        }
    }
    let mut pos = 0;
    for i in (0..dlen).rev() {
        if pos < DISPLAY_COLS {
            row[pos] = digits[i];
            pos += 1;
        }
    }
    for &b in b" bytes" {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
}

/// Render EVERY element of a supported top-level dynamic array (`<arg>.[]`).
///
/// Safety (WYSIWYS): the array's offset word lives in the static head and is
/// bound by the same `slot < static_head_words` guard as scalar fields. The
/// legacy sole-tail mode retains its exact-placement equalities; multi-tail
/// mode consumes an interval from the format-wide authenticated partition.
/// Both modes therefore bind the bytes the EVM decodes while excluding
/// aliases, gaps, and trailing data. EVERY element is rendered (or the field
/// declines-to-blind): showing a subset is the array-tail-hiding hazard.
fn resolve_array_with_mode(
    field: &FieldEntry<'_>,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
    mode: ContractCalldataMode,
) -> Result<(usize, usize), RenderErr> {
    if array_all_is_multi(ir, field.path_off)? {
        return Err(RenderErr::Reject("7730 multi-array framing"));
    }
    match mode {
        ContractCalldataMode::Standard => resolve_array(field, ir, full_body, static_head_words),
        ContractCalldataMode::MultiTail(partition) => {
            let head_end = usize::from(static_head_words)
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 arr head ovf"))?;
            if partition.head_end() != head_end || partition.body_end() != full_body.len() {
                return Err(RenderErr::Reject("7730 arr partition bounds"));
            }
            let slot = sole_array_slot(ir, field.path_off)?;
            let (_, interval) = partition.find(slot, TailKind::StaticWordArray)?;
            let count =
                usize::try_from(interval.count).map_err(|_| RenderErr::Reject("7730 arr count"))?;
            if count > MAX_ARRAY_RENDER {
                return Err(RenderErr::Reject("7730 arr over cap"));
            }
            Ok((interval.data_start, count))
        }
        ContractCalldataMode::UniswapV3Path(_) => Err(RenderErr::Reject("7730 arr mode mismatch")),
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn render_array(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
    container: &ContractContainerCtx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    render_array_with_mode(
        field,
        pages,
        ir,
        full_body,
        static_head_words,
        ContractCalldataMode::Standard,
        container,
        erc20,
        resolver,
        params,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_array_with_mode(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
    mode: ContractCalldataMode,
    container: &ContractContainerCtx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let (elems_start, count) =
        resolve_array_with_mode(field, ir, full_body, static_head_words, mode)?;
    let fmt = FormatOp::try_from(field.format_op).map_err(|_| RenderErr::Reject("7730 arr fmt"))?;

    // Canonical integer extension is independent of visibility and formatter.
    // Inspect every element before the array header or token identity page.
    for index in 0..count {
        let word = array_element_word(full_body, elems_start, index)?;
        require_integer_word_canonical(params, word)?;
    }

    // A `tokenAmount` array (Lido `requestWithdrawals(uint256[] _amounts, …)`)
    // renders every element as an amount of the SAME token — the descriptor's
    // `token` is a constant or a sibling scalar field shared by all elements.
    // Resolve + Merkle-bind it ONCE, so each element shows the verified
    // decimals/symbol. SLOT-CONFUSION DISCIPLINE: the token sub-resolution
    // reads the STATIC HEAD only (`resolve_array` already proved the array
    // offset == static_head_words*32, so the head is exactly this prefix) —
    // never the array-data tail. The exact token contract is named ONCE for
    // both bound and unbound arrays: a symbol is not injective across the
    // authenticated catalogue. Unbound elements fall back to loud raw.
    let (bound_token, token_addr): (Option<(u32, &[u8], [u8; 20])>, Option<[u8; 20]>) =
        if fmt == FormatOp::TokenAmount {
            let head_end = usize::from(static_head_words)
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 arr ovf"))?;
            let head = full_body
                .get(..head_end)
                .ok_or(RenderErr::Reject("7730 arr head oob"))?;
            let token_addr = if params.token_path.is_some() || params.token.is_some() {
                Some(resolve_token_address(ir, head, container, params)?)
            } else {
                None
            };
            let b = match (token_addr, erc20) {
                (Some(a), Some(m)) if a == m.contract => Some((u32::from(m.decimals), m.symbol, a)),
                _ => None,
            };
            (b, token_addr)
        } else {
            (None, None)
        };

    // Exactness is a format-level preflight, not an element-paint detail.
    // Inspect every authenticated scaled word before the array header, token
    // identity, or any earlier element can mutate `Pages`. Unknown-scale
    // amount/token paths deliberately remain exact raw-integer renderings.
    let scaled_format: Option<(u32, &[u8])> = match fmt {
        FormatOp::Amount => amount_decision(container.chain_id, params)
            .map(|d| (d.decimals, params.base.unwrap_or(b""))),
        FormatOp::Unit => {
            let d = unit_decision(params);
            Some((d.decimals, d.unit))
        }
        FormatOp::TokenAmount => bound_token.map(|(decimals, ticker, _)| (decimals, ticker)),
        _ => None,
    };
    let mut exact_amount_texts = [None; MAX_ARRAY_RENDER];
    if let Some((decimals, unit)) = scaled_format {
        for i in 0..count {
            let word = array_element_word(full_body, elems_start, i)?;
            exact_amount_texts[i] = Some(require_exact_amount_text(*word, decimals, unit)?);
        }
    }

    // 8. Header page: "<label>" + "<count> items" (makes the total explicit;
    //    also the count==0 page). All semantic refusal checks above are pure.
    let hp = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, hp, field.label);
    {
        let [_, r1, _r2, _r3] = pages.page_mut(hp);
        write_count_row(r1, count);
    }

    if let Some((_, _, addr)) = bound_token {
        let ap = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, ap, b"Token contract");
        let [_, ar1, ar2, ar3] = pages.page_mut(ap);
        write_addr_full(ar1, ar2, ar3, &addr);
    } else if let Some(addr) = token_addr {
        let ap = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, ap, b"Token (UNVERIFIED)");
        let [_, ar1, ar2, ar3] = pages.page_mut(ap);
        write_addr_full_or_name(ar1, ar2, ar3, &addr, container.chain_id, resolver);
    }

    // 9. One page per element — EVERY element (array-tail-hiding closed).
    for i in 0..count {
        let word32 = array_element_word(full_body, elems_start, i)?;
        render_array_element(
            field,
            fmt,
            word32,
            pages,
            container,
            bound_token,
            exact_amount_texts[i],
            resolver,
            params,
        )?;
    }
    Ok(())
}

/// Return one exact array element using the same checked offset arithmetic for
/// semantic preflight and painting. A future change therefore cannot inspect
/// one word for exactness and render another through arithmetic drift.
fn array_element_word(
    full_body: &[u8],
    elems_start: usize,
    index: usize,
) -> Result<&[u8; 32], RenderErr> {
    let delta = index
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    let start = elems_start
        .checked_add(delta)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    let end = start
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    full_body
        .get(start..end)
        .ok_or(RenderErr::Reject("7730 arr elem oob"))?
        .try_into()
        .map_err(|_| RenderErr::Reject("7730 arr elem"))
}

/// Write "<count> items" into a 16-col row (count ≤ MAX_ARRAY_RENDER).
fn write_count_row(row: &mut [u8; DISPLAY_COLS], count: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 8];
    let mut n = count;
    let mut dlen = 0;
    if n == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while n > 0 && dlen < digits.len() {
            digits[dlen] = b'0' + (n % 10) as u8;
            n /= 10;
            dlen += 1;
        }
    }
    let mut pos = 0;
    for i in (0..dlen).rev() {
        if pos < DISPLAY_COLS {
            row[pos] = digits[i];
            pos += 1;
        }
    }
    for &b in b" items" {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
}

/// Render one array element (a 32-byte word) as one page. v1 supports the
/// element formats that make sense for a list: amount, tokenAmount,
/// addressName, raw. `bound_token` is the `(decimals, symbol, contract)` of the
/// array's shared token, Merkle-bound ONCE by [`render_array`] (`None` = not
/// bound / not a tokenAmount array) — never re-resolved per element. Keeping
/// The caller emits the shared token's exact identity once before the elements,
/// so raw-overflow pages do not repeat it per item.
#[allow(clippy::too_many_arguments)]
fn render_array_element(
    field: &FieldEntry<'_>,
    fmt: FormatOp,
    word: &[u8; 32],
    pages: &mut Pages,
    container: &ContractContainerCtx,
    bound_token: Option<(u32, &[u8], [u8; 20])>,
    exact_amount_text: Option<ExactAmountText>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    match fmt {
        FormatOp::Amount => {
            let value = U256(*word);
            let Some(_amount) = amount_decision(container.chain_id, params) else {
                let [_, r1, r2, foot] = pages.page_mut(p);
                let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, true, "");
                if fit == AmountFit::Full {
                    write_line(foot, "! raw, dec=?");
                    return Ok(());
                }
                return write_raw_word_two_pages(pages, p, field.label, word);
            };
            // Preserve the existing array display contract: unlike scalar
            // native `amount`, an array carries a unit only when the descriptor
            // explicitly supplies `base`. The known-chain lookup above is used
            // solely to authenticate the otherwise-default 18-decimal scale.
            let [_, r1, r2, foot] = pages.page_mut(p);
            let amount_text = exact_amount_text.expect("scaled amount array was precomputed");
            amount_text.paint(r1, r2);
            write_line(foot, "> next");
            pages.mark_nav(p, 3);
            Ok(())
        }
        FormatOp::Unit => {
            // A value with a unit suffix (e.g. a percentage list) — same shape
            // as the scalar `render_unit` (decimals default 0 + the unit string).
            if params.prefix.is_some_and(|v| v != 0) || params.suffix.is_some() {
                return Err(RenderErr::Reject("7730 unit affix unsupported"));
            }
            let [_, r1, r2, foot] = pages.page_mut(p);
            let amount_text = exact_amount_text.expect("scaled unit array was precomputed");
            amount_text.paint(r1, r2);
            write_line(foot, "> next");
            pages.mark_nav(p, 3);
            Ok(())
        }
        FormatOp::TokenAmount => {
            // Amount of the array's shared token. `bound_token` was resolved +
            // Merkle-verified once by the caller. Bound → scaled value + symbol;
            // unbound → loud RAW integer (audit M-4: never scale with an
            // assumed decimals), with the token identity already named once by
            // the caller's `Token (UNVERIFIED)` page.
            let value = U256(*word);
            let [_, r1, r2, foot] = pages.page_mut(p);
            match bound_token {
                Some((_decimals, _ticker, _token_contract)) => {
                    let amount_text =
                        exact_amount_text.expect("bound token amount array was precomputed");
                    amount_text.paint(r1, r2);
                    write_line(foot, "> next");
                    pages.mark_nav(p, 3);
                }
                None => {
                    let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, true, "");
                    if fit == AmountFit::Full {
                        write_line(foot, "! raw, dec=?");
                    } else {
                        return write_raw_word_two_pages(pages, p, field.label, word);
                    }
                }
            }
            Ok(())
        }
        FormatOp::AddressName => {
            let a = canonical_address_word(word)?;
            let [_, r1, r2, r3] = pages.page_mut(p);
            if params.addr_types.is_some() || params.addr_sources.is_some() {
                write_addr_full(r1, r2, r3, &a);
            } else {
                write_addr_full_or_name(r1, r2, r3, &a, container.chain_id, resolver);
            }
            Ok(())
        }
        FormatOp::Raw => {
            // The array-element sibling of the scalar `render_raw` fix. The old
            // form passed two 16-byte slices to `write_hex_word` (caps at 8
            // bytes/row), silently dropping bytes 8..16 and 24..32 — a BE
            // uint256 < 2^64 rendered as all-zeros (WYSIWYS magnitude-hiding,
            // finding 1.2). Spill across two pages via the shared helper so
            // every signed byte shows. `p` was already pushed + labelled above.
            write_raw_word_two_pages(pages, p, field.label, word)
        }
        _ => Err(RenderErr::Reject("7730 arr elem fmt unsup")),
    }
}

/// Decode a canonical ABI/EIP-712 address word. Dirty high padding changes the
/// signed hash while leaving the low 20 displayed bytes unchanged, so it must
/// decline rather than be visually laundered as the same address.
fn canonical_address_word(word: &[u8; 32]) -> Result<[u8; 20], RenderErr> {
    if word[..12].iter().any(|&b| b != 0) {
        return Err(RenderErr::Reject("7730 noncanonical address"));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&word[12..]);
    Ok(addr)
}

fn render_enum(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    _container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Resolve the field's value (a single static-head word). `@`-container
    // enums are not a shape any descriptor uses, so a container resolution
    // is refused rather than guessed.
    let value: [u8; 32] = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(_) => return Err(RenderErr::Reject("7730 enum on container")),
    };
    // ABI `bool` has exactly two canonical words: 0 and 1. Unsigned enums may
    // render an unknown key as its exact raw integer, but applying that rule to
    // a Bool terminal would make malformed ABI words look like meaningful
    // boolean choices. Refuse before publishing any page instead.
    if params.terminal_kind == Some(crate::render::policy::TerminalKind::Bool)
        && (value[..31].iter().any(|&byte| byte != 0) || value[31] > 1)
    {
        return Err(RenderErr::Reject("7730 noncanonical bool enum"));
    }
    // The descriptor MUST carry an `enum_ref` → the interned value→label
    // table; without it there is nothing to resolve against.
    let enum_off = params
        .enum_ref
        .ok_or(RenderErr::Reject("7730 enum no ref"))?;
    // Audit M-7: render the RESOLVED label, never a garbled gloss. A malformed
    // table still declines. An UNKNOWN value (not in the declared set) renders
    // the raw index loudly instead of declining the whole tx (review 3.3, spec:
    // "an enum value outside the set is shown as its raw value"). Showing the
    // exact signed integer + a loud `! enum: unknown` marker is WYSIWYS-honest
    // (the user sees the real value, not a substituted gloss) and strictly more
    // informative than blind-signing everything.
    let Some(label) = crate::render::enums::lookup_enum_label(ir.pool, enum_off, &value)? else {
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_label_row(pages, p, field.label);
        let fit = {
            let [_, r1, r2, foot] = pages.page_mut(p);
            let fit = write_amount_two_rows(r1, r2, &U256(value), 0, 6, true, true, "");
            if fit == AmountFit::Full {
                write_line(foot, "! enum: unknown");
            }
            fit
        };
        return if fit == AmountFit::Full {
            Ok(())
        } else {
            write_raw_word_two_pages(pages, p, field.label, &value)
        };
    };
    // A label longer than the three value rows would have to be truncated
    // on the trusted display — refuse rather than show a partial gloss.
    if label.len() > 3 * DISPLAY_COLS {
        return Err(RenderErr::Reject("7730 enum label too long"));
    }
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    let rows: [&mut [u8; DISPLAY_COLS]; 3] = [r1, r2, r3];
    let mut chunks = label.chunks(DISPLAY_COLS);
    for row in rows {
        match chunks.next() {
            Some(c) => write_line_bytes(row, c),
            None => write_line_bytes(row, b""),
        }
    }
    Ok(())
}

fn render_unit(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    // Decision half factored to `amount_decision::unit_decision` (M4):
    // decimals default 0 (a bare count), unit defaults empty — the 18-vs-0
    // asymmetry with `render_amount` is ∀-pinned there.
    let d = unit_decision(params);
    let amount_text = require_exact_amount_text(bytes, d.decimals, d.unit)?;
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    {
        let [_, r1, r2, foot] = pages.page_mut(p);
        amount_text.paint(r1, r2);
        write_line(foot, "> next");
        pages.mark_nav(p, 3);
    }
    Ok(())
}

fn render_chain_id(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    // FAITHFUL formatter (audit 2026-06-26 — faithless-formatter class). Render
    // the chain id at the field's OWN signed word, not the container chain id
    // unconditionally. The old body discarded `field.path`/`body`, so a field
    // pointing at a calldata / typed-data word (e.g. a cross-chain bridge's
    // destination chain) displayed the UserOp's *execution* chain while the
    // signature committed to a different value (display != signed) — and the
    // host completeness lint still credited the field as covered, so the gap
    // shipped unwarned. `@.chainId` resolves through the container arm to
    // the container chain id, preserving the envelope use-case.
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(container, idx)?,
    };
    let [_, r1, r2, foot] = pages.page_mut(p);
    match read_u64_be_tail(&bytes) {
        Some(cid) if decimal_digits(cid) <= DISPLAY_COLS => {
            // "<decimal id>" on row 1, "<chain_name>" on row 2.
            let mut decimal = [b' '; DISPLAY_COLS];
            write_decimal_into(&mut decimal, 0, cid);
            *r1 = decimal;
            write_line(r2, chain_name(cid));
        }
        // A 17-20 digit chain id is <= u64 but cannot be shown in full on a
        // 16-col row, and names no real EVM chain. Fail loud rather than let
        // `write_decimal_into` silently drop the low digits (which would paint
        // a different, smaller chain number than the one signed) — same policy
        // as the >u64 arm below.
        Some(_) => return write_raw_word_two_pages(pages, p, field.label, &bytes),
        // A chain id wider than u64 cannot name a real EVM chain; fail loud
        // rather than render a truncated low-64-bit value (same policy as the
        // date / duration `>2^64` guard).
        None => return write_raw_word_two_pages(pages, p, field.label, &bytes),
    }
    write_line(foot, "> next");
    pages.mark_nav(p, 3);
    Ok(())
}

fn render_token_ticker(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    // FAITHFUL formatter (audit 2026-06-26 — faithless-formatter class). The
    // token is the field's OWN resolved address word (FMT_TOKEN_TICKER carries
    // no `tokenPath` param — dbgen emits none), so resolve `field.path` rather
    // than a param. The old body resolved only `params.tokenPath`/`token`
    // (always absent here, so it ALWAYS fell to "(unknown token)") and, when
    // unbound, hid the token IDENTITY outright — yet the completeness lint
    // credits `field.path` as covered, so the signed token operand went unshown.
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => canonical_address_word(b)?,
        Resolved::Container(idx) => container_addr(container, idx)?,
    };
    match erc20 {
        Some(meta) if addr == meta.contract => {
            let [_, r1, _r2, foot] = pages.page_mut(p);
            write_line_bytes(r1, meta.symbol);
            write_line(foot, "> next");
            pages.mark_nav(p, 3);
            // Symbols are not unique, even inside the authenticated token
            // catalogue. Always follow the friendly ticker with the exact
            // contract so two signed token operands cannot paint identically.
            let ap = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
            write_label_row(pages, ap, b"Token contract");
            let [_, ar1, ar2, ar3] = pages.page_mut(ap);
            write_addr_full(ar1, ar2, ar3, &addr);
        }
        // No Merkle-verified ticker for this address — NEVER hide the token
        // identity. Show the full 40-hex address (resolver-aware) across rows
        // 1-3 so the signed token operand is always on the trusted display
        // (mirrors render_token_amount's unbound "Token (UNVERIFIED)" page).
        _ => {
            let [_, r1, r2, r3] = pages.page_mut(p);
            write_addr_full_or_name(r1, r2, r3, &addr, container.chain_id, resolver);
        }
    }
    Ok(())
}

fn render_interop_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    _resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    // ERC-3770 long form: `eip155:<chainId>:0x<addr>`. The chain short-
    // name registry is out of scope (would require a separate name DB
    // on-device); long form is unambiguous and self-describing.
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => canonical_address_word(b)?,
        Resolved::Container(idx) => container_addr(container, idx)?,
    };
    let p1 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p1, field.label);
    let [_, scheme, id_head, id_tail] = pages.page_mut(p1);
    write_line(scheme, "eip155:");
    let mut digits = [0u8; 20];
    let n = format_u64(container.chain_id, &mut digits)
        .ok_or(RenderErr::Reject("7730 interop chain overflow"))?;
    if n + 1 <= DISPLAY_COLS {
        id_head[..n].copy_from_slice(&digits[..n]);
        id_head[n] = b':';
        write_line(id_tail, "> next");
        pages.mark_nav(p1, 3);
    } else {
        // A u64 has at most 20 digits. Fifteen digits plus a visible
        // continuation marker fill row 2; the remaining five plus ':' fit
        // row 3. Every signed chain-id digit reaches the display.
        const FIRST: usize = DISPLAY_COLS - 1;
        id_head[..FIRST].copy_from_slice(&digits[..FIRST]);
        id_head[FIRST] = b'>';
        let rest = n - FIRST;
        id_tail[..rest].copy_from_slice(&digits[FIRST..n]);
        id_tail[rest] = b':';
    }

    let p2 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p2, 0), "Address:");
    let [_, r1, r2, r3] = pages.page_mut(p2);
    write_addr_full(r1, r2, r3, &addr);
    Ok(())
}

fn render_encrypted(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // WYSIWYS (audit 2026-06-29 — encrypted formatter signed-but-not-shown).
    //
    // The old body painted a benign "[ENCRYPTED]" + descriptor-pinned
    // `fallback_label` page and returned `Ok(())` WITHOUT ever resolving the
    // field's path — so the 32-byte signed operand at that path (a recipient,
    // an amount, a spender) was committed to the digest but NEVER shown, on a
    // page that looks like a normal clear-sign confirmation. It was the only
    // formatter that "succeeds" while hiding a signed value; every sibling
    // (`render_enum`, `render_nft_name`, …) rejects when it cannot faithfully
    // display, which hard-refuses a verified/known call.
    // Because the field is a normal *visible* field (not `visible:"never"`),
    // the dbgen H-3 coverage lint credited it as shown — there was no build-
    // time or on-device signal that an operand was hidden.
    //
    // There is no honest way to clear-sign a value the format says to hide, so
    // REJECT exactly like `render_enum`: the dispatcher refuses both UserOp
    // and off-chain typed paths. `dbgen::parse_format_name` additionally refuses `format:
    // "encrypted"` at build time, so the pinned corpus can never emit this
    // opcode — this arm is the runtime safety net if a hand-built TLV ever
    // sets 0x0E.
    let _ = (field, pages, params);
    Err(RenderErr::Reject("7730 encrypted field"))
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

pub(super) fn write_label_row(pages: &mut Pages, page: usize, label: &[u8]) {
    let row = pages.row_mut(page, 0);
    // A field label lands on row 0; the value fills rows 1..3 and the footer.
    // On the 4-row page there is no free row to wrap a long label onto (a true
    // multi-row label would need its own page — see
    // `docs/erc7730-renderer-fuzzability.md`), so a label longer than the row
    // is truncated. ~18.8% of registry labels exceed 16 cols, and a SILENT cut
    // ("Amount to withdraw" → "Amount to withdr") hides that the label is
    // incomplete — reserve the last cell for a `~` truncation marker so the
    // user can tell the label continues. Reuses blind_sign's ASCII-into-16-col
    // semantics for the fitting case.
    if label.len() > DISPLAY_COLS {
        write_line_bytes(row, &label[..DISPLAY_COLS - 1]);
        row[DISPLAY_COLS - 1] = b'~';
    } else {
        write_line_bytes(row, label);
    }
}

pub(super) fn write_line_bytes(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let n = text.len().min(DISPLAY_COLS);
    row[..n].copy_from_slice(&text[..n]);
}

/// Write up to **8 bytes** as hex (≤16 chars) into a 16-col row. A 16-col row
/// holds 16 hex chars = 8 bytes, so a slice longer than 8 bytes is **silently
/// clamped to its first 8 bytes** — callers MUST pass ≤8-byte slices. A full
/// 32-byte word therefore needs FOUR rows across two pages; use
/// [`write_raw_word_two_pages`] (never two 16-byte slices, which drop the
/// low-order half — the WYSIWYS magnitude-hiding bug fixed 2026-06-26 for the
/// scalar path and 2026-07 for the array-element path, finding 1.2). We
/// deliberately omit the "0x" prefix so the hex fills the row.
fn write_hex_word(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let take = bytes.len().min(DISPLAY_COLS / 2);
    for (i, &b) in bytes[..take].iter().enumerate() {
        row[i * 2] = hex_nibble(b >> 4);
        row[i * 2 + 1] = hex_nibble(b & 0x0F);
    }
}

/// Render a full 32-byte word as hex across TWO pages (four 8-byte rows), so
/// EVERY signed byte is shown. A single page holds only 16 hex bytes, so a
/// one-page form silently drops bytes 16..32 — the entire low-order half of a
/// big-endian uint256, making any value < 2^128 render as leading-zeros and
/// any value < 2^64 render as all-zeros (WYSIWYS magnitude-hiding). The scalar
/// (`render_raw`) and array-element (`render_array_element`) Raw paths MUST
/// share this helper so a fix to one reaches both (they diverged once —
/// finding 1.2). The FIRST page must already be pushed and label-written
/// (`first_page`); the second is pushed + labelled here.
fn write_raw_word_two_pages(
    pages: &mut Pages,
    first_page: usize,
    label: &[u8],
    word: &[u8; 32],
) -> Result<(), RenderErr> {
    {
        let [_, r1, r2, foot] = pages.page_mut(first_page);
        write_hex_word(r1, &word[0..8]);
        write_hex_word(r2, &word[8..16]);
        write_line(foot, "1/2 > next");
        pages.mark_nav(first_page, 3);
    }
    let p2 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p2, label);
    let [_, r1, r2, foot] = pages.page_mut(p2);
    write_hex_word(r1, &word[16..24]);
    write_hex_word(r2, &word[24..32]);
    write_line(foot, "2/2 > next");
    pages.mark_nav(p2, 3);
    Ok(())
}

#[inline]
pub(super) fn hex_nibble(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        v => b'a' + (v - 10),
    }
}

/// Read the low 8 bytes of a 32-byte BE word as a u64, requiring the
/// high 24 bytes to be zero. Returns `None` when the signed value exceeds
/// `u64` — the caller MUST then render the complete raw value (or reject)
/// rather than paint a silently-truncated date/duration. A companion controls these
/// `uint256` words, so the pre-2026-06-23 silent truncation let a benign
/// low-64-bit timestamp display while an unbounded validity window was
/// signed (audit 2026-06-23 — date/duration high-byte truncation).
fn read_u64_be_tail(bytes: &[u8; 32]) -> Option<u64> {
    if bytes[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(bytes[24..].try_into().unwrap()))
}

/// Number of decimal digits needed to render `n` (`0` counts as one
/// digit). Used by the magnitude-critical formatters (block-height date,
/// chain id) to detect — BEFORE painting — that `write_decimal_into` would
/// have to drop low-order digits to fit the row, so they can render the
/// full value across rows or fail loud instead of silently understating
/// the signed magnitude.
pub(super) fn decimal_digits(n: u64) -> usize {
    let mut count = 1usize;
    let mut m = n / 10;
    while m > 0 {
        count += 1;
        m /= 10;
    }
    count
}

/// Format a u64 as decimal at `out[pos..]`. Returns the new position.
///
/// NOTE: this STOPS at the end of the row, silently dropping any digits
/// that don't fit (it writes most-significant-first). That is acceptable
/// only for callers where a dropped low-order digit is cosmetic
/// (`format_duration`'s sub-day components, the interop chain-label
/// prefix). Callers rendering a security-critical magnitude must gate on
/// [`decimal_digits`] first — see `render_date` (blockHeight) and
/// `render_chain_id` — so a magnitude is never silently understated.
pub(super) fn write_decimal_into(out: &mut [u8; DISPLAY_COLS], pos: usize, mut n: u64) -> usize {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if n == 0 {
        if pos < out.len() {
            out[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut p = pos;
    for j in (0..i).rev() {
        if p >= out.len() {
            break;
        }
        out[p] = buf[j];
        p += 1;
    }
    p
}

/// Render unix-seconds `secs` into rows `r1` + `r2` as `YYYY-MM-DD` /
/// `HH:MM:SS UTC`. Always-fits since the format is < 16 chars per row.
fn format_iso8601_utc(secs: u64, r1: &mut [u8; DISPLAY_COLS], r2: &mut [u8; DISPLAY_COLS]) -> bool {
    let (year, mon, day, hour, min, sec) = unix_to_ymdhms(secs);

    // WYSIWYS (audit 2026-06-26 — date year truncation). The 4-digit
    // "YYYY" field can only honestly show years 0..=9999. `read_u64_be_tail`
    // accepts any timestamp <= u64::MAX (year ~584e9), and the prior
    // `as u16` cast in `unix_to_ymdhms` wrapped the year mod 65536 — so a
    // perpetual EIP-3009 `validBefore` (true year ~67570, unix ~2.07e12)
    // rendered as a benign "2034" while the signature committed to an
    // effectively-unbounded validity window. Fail LOUD, matching the
    // sibling `! TIME >2^64` guard, so a far-future expiry can never read
    // as a near one (display != signed).
    if !(0..=9999).contains(&year) {
        return false;
    }
    let year = year as u16; // safe: 0..=9999 after the guard above

    for cell in r1.iter_mut() {
        *cell = b' ';
    }
    for cell in r2.iter_mut() {
        *cell = b' ';
    }

    // Row 1: "YYYY-MM-DD" (10 chars), padded.
    write_2digit(&mut r1[0..2], (year / 100) as u8);
    write_2digit(&mut r1[2..4], (year % 100) as u8);
    r1[4] = b'-';
    write_2digit(&mut r1[5..7], mon);
    r1[7] = b'-';
    write_2digit(&mut r1[8..10], day);

    // Row 2: "HH:MM:SS UTC" (12 chars).
    write_2digit(&mut r2[0..2], hour);
    r2[2] = b':';
    write_2digit(&mut r2[3..5], min);
    r2[5] = b':';
    write_2digit(&mut r2[6..8], sec);
    r2[9] = b'U';
    r2[10] = b'T';
    r2[11] = b'C';
    true
}

fn write_2digit(out: &mut [u8], n: u8) {
    out[0] = b'0' + (n / 10) % 10;
    out[1] = b'0' + (n % 10);
}

/// Convert unix seconds → `(year, month, day, hour, min, sec)` UTC.
/// Civil-from-days algorithm by Howard Hinnant (public domain).
fn unix_to_ymdhms(secs: u64) -> (i64, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let hour = (sod / 3600) as u8;
    let min = ((sod % 3600) / 60) as u8;
    let sec = (sod % 60) as u8;

    // Civil-from-days: offset by 719_468 so 1970-01-01 → 0.
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    // Full i64 year — deliberately NOT truncated to u16. The old `as u16`
    // cast wrapped the year mod 65536, so a far-future timestamp (a u64
    // second count `read_u64_be_tail` accepts) rendered as a benign near
    // year. `format_iso8601_utc` now fails loud on any year outside
    // 0..=9999 (audit 2026-06-26 — date year truncation).
    let year = y + if m <= 2 { 1 } else { 0 };

    (year, m, d, hour, min, sec)
}

/// "Xd Yh Zm Ws" duration into a single row. Omits leading zero
/// components.
fn format_duration(mut secs: u64, row: &mut [u8; DISPLAY_COLS]) -> bool {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let d = secs / 86_400;
    secs %= 86_400;
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;
    // Preflight the complete textual representation. `write_decimal_into`
    // intentionally clamps to the row, so without this check a huge day count
    // would silently drop the later components and collide with other signed
    // durations.
    let needed = (if d > 0 { decimal_digits(d) + 2 } else { 0 })
        + (if h > 0 || d > 0 {
            decimal_digits(h) + 2
        } else {
            0
        })
        + (if m > 0 || h > 0 || d > 0 {
            decimal_digits(m) + 2
        } else {
            0
        })
        + decimal_digits(s)
        + 1;
    if needed > DISPLAY_COLS {
        return false;
    }
    let mut pos = 0usize;
    if d > 0 {
        pos = write_decimal_into(row, pos, d);
        if pos < row.len() {
            row[pos] = b'd';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, h);
        if pos < row.len() {
            row[pos] = b'h';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if m > 0 || h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, m);
        if pos < row.len() {
            row[pos] = b'm';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    pos = write_decimal_into(row, pos, s);
    if pos < row.len() {
        row[pos] = b's';
    }
    true
}

/// Resolve the token contract address from a `tokenAmount` /
/// `tokenTicker` field's parameters: `params.token_path` wins, then
/// `params.token` literal.
pub(super) fn resolve_token_address(
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    container: &ContractContainerCtx,
    params: &ParamSet<'_>,
) -> Result<[u8; 20], RenderErr> {
    if let Some(tp) = params.token_path {
        // tp is a path program (NO leading length byte — dbgen pushes it raw via
        // `push_tlv(PARAM_TOKEN_PATH, &prog)`). A `RootStructured` tokenPath goes
        // through the hardened `resolve::resolve_token_address`, which handles the
        // static-word case (`params.tokenIn`) AND the Tier-B extraction ops
        // (`params.path.[0:20]`, `path.[-1]`) that pull a token id out of a
        // dynamic swap leg. Container / other roots keep the legacy word→low-20.
        if tp.is_empty() {
            return Err(RenderErr::Reject("7730 empty tokpath"));
        }
        let root =
            PathOp::try_from(tp[0]).map_err(|_| RenderErr::Reject("7730 bad tokpath root"))?;
        return match root {
            PathOp::RootStructured => crate::render::resolve::resolve_token_address(&tp[1..], body),
            _ => canonical_address_word(&resolve_path_bytes(tp, body, container)?),
        };
    }
    if let Some(t) = params.token {
        return Ok(*t);
    }
    let _ = ir;
    Err(RenderErr::Reject("7730 no token"))
}

/// Resolve a path program (raw, no length prefix) to a 32-byte word.
/// Mirrors [`resolve_path`] but operates on a pre-extracted program
/// slice — used by `tokenPath` which is stored as a raw program inside
/// the parameter TLV blob.
fn resolve_path_bytes(
    prog: &[u8],
    body: &[u8],
    container: &ContractContainerCtx,
) -> Result<[u8; 32], RenderErr> {
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }
    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let mut p = 1usize;

    match root {
        PathOp::RootStructured => {
            let mut slot = 0usize;
            while p < prog.len() {
                let op = PathOp::try_from(prog[p]).map_err(|_| RenderErr::Reject("7730 bad op"))?;
                p += 1;
                match op {
                    PathOp::FieldIdx => {
                        if p + 2 > prog.len() {
                            return Err(RenderErr::Reject("7730 trunc field"));
                        }
                        let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
                        p += 2;
                        slot = slot
                            .checked_add(idx)
                            .ok_or(RenderErr::Reject("7730 slot ovf"))?;
                    }
                    _ => return Err(RenderErr::Reject("7730 path p4 unsup")),
                }
            }
            let start = slot
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let end = start
                .checked_add(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let word = body
                .get(start..end)
                .ok_or(RenderErr::Reject("7730 short body"))?;
            let mut out = [0u8; 32];
            out.copy_from_slice(word);
            Ok(out)
        }
        PathOp::RootContainer => {
            if p + 3 != prog.len() || prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad"));
            }
            let idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            match idx {
                container_field::TO => {
                    let mut out = [0u8; 32];
                    out[12..].copy_from_slice(&container.target);
                    Ok(out)
                }
                _ => container_u256(container, idx),
            }
        }
        _ => Err(RenderErr::Reject("7730 path no root")),
    }
}

#[cfg(test)]
mod walker_slot_confusion_fixed {
    //! REGRESSION (clear-signing forgery — FIXED): the walker computes a
    //! head-word slot by SUMMING `FieldIdx` values. That is correct ONLY
    //! when each emitted `FieldIdx` is the field's true ABI *head-word
    //! offset*. dbgen now emits exactly that (see
    //! `dbgen::erc7730::compile_structured_contract_path`); previously it
    //! emitted a logical ordinal, so a field preceded by a multi-word
    //! static type (fixed array `T[N]`, non-leading static tuple)
    //! resolved to the wrong word and the trusted display showed one
    //! value while the contract executed on another.
    //!
    //! These tests pin the on-device half: fed a correctly-compiled
    //! head-slot program, the walker reads the EVM-decoded word (display
    //! == signed); and the head-bound guard rejects any slot that reaches
    //! past the format's static head. See
    //! `docs/security/vulns/VULN-erc7730-walker-slot-confusion.md`.
    use super::*;
    use crate::ir::{ContextKind, Erc7730Ir};

    /// Build a throwaway `Erc7730Ir` whose `pool` holds a single compiled
    /// path program at offset 1. Only `pool` matters for `resolve_path`.
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
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

    /// Encode the calldata BODY (post-selector) for
    /// `f(uint256[3] arr, address to)`. ABI head layout:
    ///   word0 = arr[0], word1 = arr[1], word2 = arr[2], word3 = to.
    fn body_uint3arr_then_addr(arr1_marker: u8, real_to: [u8; 20]) -> [u8; 128] {
        let mut body = [0u8; 128];
        body[32 + 12..32 + 32].copy_from_slice(&[arr1_marker; 20]); // arr[1]
        body[96 + 12..96 + 32].copy_from_slice(&real_to); // to (word 3)
        body
    }

    fn addr_of(w: Resolved<'_>) -> [u8; 20] {
        match w {
            Resolved::Slot32(b) => {
                let mut a = [0u8; 20];
                a.copy_from_slice(&b[12..]);
                a
            }
            Resolved::Container(_) => panic!("unexpected container"),
        }
    }

    #[test]
    fn walker_reads_to_with_head_slot_program() {
        // dbgen now emits `to`'s ABI head-word slot 3 (it is preceded by
        // the 3-word `uint256[3] arr`), encoded as `FieldIdx(3)`.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x03, // FieldIdx(3) — head-word slot, NOT logical ordinal 1
        ];
        let ir = ir_with_path(&prog);

        let arr1_marker = 0xBE; // attacker-controlled benign-looking word 1
        let real_to = [0xADu8; 20]; // the address the EVM actually uses
        let body = body_uint3arr_then_addr(arr1_marker, real_to);

        let shown = addr_of(resolve_path(&ir, 1, &body).expect("path resolves"));

        // DISPLAY == SIGNED: the walker reads head word 3 — the exact word
        // the EVM decodes as `to`. The attacker can no longer divert the
        // displayed recipient by stuffing word 1.
        assert_eq!(shown, real_to, "walker reads the EVM-decoded `to` (word 3)");
        assert_ne!(shown, [arr1_marker; 20], "walker does NOT read arr[1]");
    }

    #[test]
    fn nested_static_tuple_slot_sums_to_head_word() {
        // `g((uint256 a, uint256 b) s, address to)`: `to` is at ABI head
        // word 2 (the static tuple inlines 2 words). dbgen emits
        // FieldIdx(2) [tuple base] + FieldIdx(0) summing to 2. The walker
        // reads word 2.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x02, // tuple base offset (s occupies words 0..2)
            PathOp::FieldIdx as u8,
            0x00,
            0x00, // (+0) — `to` follows the tuple
        ];
        let ir = ir_with_path(&prog);
        let mut body = [0u8; 96];
        let real_to = [0xCDu8; 20];
        body[64 + 12..64 + 32].copy_from_slice(&real_to); // word 2 = to
        let shown = addr_of(resolve_path(&ir, 1, &body).expect("resolves"));
        assert_eq!(shown, real_to, "summed head slot 2 reads the real `to`");
    }

    #[test]
    fn head_bound_guard_rejects_out_of_head_slot() {
        // A (malformed) program whose slot reaches word 3 while the format
        // declares a 2-word static head. `head_bounded_body` truncates the
        // body to 2 words, so the walker's bounds check rejects the read
        // instead of resolving into the dynamic tail.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x03, // slot 3 — past the 2-word static head
        ];
        let ir = ir_with_path(&prog);
        let full_body = [0u8; 128]; // 4 words on the wire
        let bounded = super::super::head_bounded_body(&full_body, 2).expect("2-word head present");
        assert_eq!(bounded.len(), 64, "body clamped to the 2-word static head");
        assert!(
            resolve_path(&ir, 1, bounded).is_err(),
            "slot past the static head is rejected, not silently rendered"
        );
    }

    #[test]
    fn head_bound_guard_rejects_short_head() {
        // Calldata too short to even contain the declared static head.
        let short = [0u8; 32]; // 1 word, but the format needs 2
        assert!(super::super::head_bounded_body(&short, 2).is_err());
    }
}

#[cfg(test)]
mod semantic_manifest_tests {
    use super::{formatter_route, FormatterRoute};
    use crate::ir::FormatOp;

    #[test]
    fn stable_opcodes_map_to_the_routes_production_dispatches() {
        const IMPLEMENTED: &str = "implemented renderer (fail closed on invalid input)";
        let expected = [
            (0x01, "raw", FormatterRoute::Raw, IMPLEMENTED),
            (0x02, "amount", FormatterRoute::Amount, IMPLEMENTED),
            (
                0x03,
                "tokenAmount",
                FormatterRoute::TokenAmount,
                IMPLEMENTED,
            ),
            (0x04, "nftName", FormatterRoute::NftName, IMPLEMENTED),
            (0x05, "date", FormatterRoute::Date, IMPLEMENTED),
            (0x06, "duration", FormatterRoute::Duration, IMPLEMENTED),
            (
                0x07,
                "addressName",
                FormatterRoute::AddressName,
                IMPLEMENTED,
            ),
            (0x08, "enum", FormatterRoute::Enum, IMPLEMENTED),
            (0x09, "unit", FormatterRoute::Unit, IMPLEMENTED),
            (
                0x0A,
                "calldata",
                FormatterRoute::HardRefuseCalldata,
                "one-level proof-set child renderer for exact firmware enrollments; otherwise hard refusal (production enrollments: 0)",
            ),
            (0x0B, "chainId", FormatterRoute::ChainId, IMPLEMENTED),
            (
                0x0C,
                "tokenTicker",
                FormatterRoute::TokenTicker,
                IMPLEMENTED,
            ),
            (
                0x0D,
                "interoperableAddressName",
                FormatterRoute::InteroperableAddressName,
                IMPLEMENTED,
            ),
            (
                0x0E,
                "encrypted",
                FormatterRoute::HardRefuseEncrypted,
                "hard refusal (signed operand hidden)",
            ),
            (
                0x0F,
                "uniswapV3Path",
                FormatterRoute::UniswapV3Path,
                IMPLEMENTED,
            ),
        ];

        assert_eq!(FormatOp::ALL.len(), expected.len());
        for (op, (wire, registry_name, route, manifest_status)) in
            FormatOp::ALL.into_iter().zip(expected)
        {
            assert_eq!(op as u8, wire);
            assert_eq!(op.registry_name(), registry_name);
            assert_eq!(FormatOp::try_from(wire), Ok(op));
            assert_eq!(formatter_route(op), route);
            assert_eq!(route.manifest_status(), manifest_status);
        }
    }

    #[test]
    fn all_covers_every_accepted_wire_byte_exactly_once() {
        let mut accepted = 0usize;
        for wire in u8::MIN..=u8::MAX {
            match FormatOp::try_from(wire) {
                Ok(op) => {
                    accepted += 1;
                    assert_eq!(
                        FormatOp::ALL.iter().filter(|&&listed| listed == op).count(),
                        1,
                        "accepted opcode 0x{wire:02x} must occur exactly once in ALL"
                    );
                }
                Err(_) => assert_eq!(
                    FormatOp::ALL
                        .iter()
                        .filter(|&&listed| listed as u8 == wire)
                        .count(),
                    0,
                    "rejected opcode 0x{wire:02x} must not occur in ALL"
                ),
            }
        }
        assert_eq!(accepted, FormatOp::ALL.len());
    }
}

#[cfg(test)]
mod date_overflow_fixed {
    //! REGRESSION (audit 2026-06-23 — date/duration high-byte truncation).
    //! `read_u64_be_tail` used to keep only the low 8 bytes of a signed
    //! `uint256`, so a companion-controlled `validBefore` / `validAfter`
    //! with non-zero high bytes displayed a benign low-64-bit timestamp
    //! while an unbounded validity window was signed. The reader now
    //! rejects any value above `u64::MAX`; the date/duration renderers
    //! route `None` to the complete two-page raw-value fallback.
    use super::read_u64_be_tail;

    #[test]
    fn high_bytes_set_returns_none() {
        let mut w = [0u8; 32];
        w[23] = 1; // first byte above the low-8 tail
        assert_eq!(read_u64_be_tail(&w), None);
    }

    #[test]
    fn u64_range_round_trips() {
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(read_u64_be_tail(&w), Some(u64::MAX));
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(read_u64_be_tail(&five), Some(5));
        assert_eq!(read_u64_be_tail(&[0u8; 32]), Some(0));
    }
}

#[cfg(test)]
mod date_year_truncation_fixed {
    //! REGRESSION (audit 2026-06-26 — date year `u16` truncation).
    //!
    //! `read_u64_be_tail` accepts every timestamp `<= u64::MAX`, but
    //! `unix_to_ymdhms` used to cast the computed year `as u16`, wrapping it
    //! mod 65536. A companion-controlled `validBefore` (EIP-3009
    //! `TransferWithAuthorization`, the pinned `circle-usdc-twa` descriptor,
    //! `format:"date"`) of true year 67570 (unix ~2.07e12) therefore
    //! rendered the benign "2034" while the signature committed to an
    //! effectively-perpetual validity window — a display != signed gap and
    //! the unfixed residual of the 2026-06-23 `>2^64` fix. The renderer now
    //! returns the full i64 year and reports that the compact representation is
    //! unavailable outside 0..=9999; the caller then renders the full raw word.
    use super::{format_iso8601_utc, unix_to_ymdhms, DISPLAY_COLS};

    #[test]
    fn unix_to_ymdhms_returns_untruncated_year() {
        // 2.1e12 s ≈ year 68515 — far past the 4-digit field but within the
        // u64 the date reader accepts. The year must come back whole, never
        // wrapped (68515 mod 65536 = 2979 was the pre-fix lie).
        let (year, ..) = unix_to_ymdhms(2_100_000_000_000);
        assert!(year > 9999, "year must not wrap; got {year}");
        assert_ne!(year, 2979, "year must not be the mod-65536 wrap value");
    }

    #[test]
    fn far_future_timestamp_within_u64_requests_raw_fallback() {
        // The concrete exploit vector: a perpetual `validBefore` that the
        // reader passes (<= u64::MAX) must NEVER render as a plausible near
        // year. It must refuse the compact date representation.
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(!format_iso8601_utc(2_100_000_000_000, &mut r1, &mut r2));
        // And crucially must not read as any benign near year.
        assert_ne!(&r1[..4], b"2979");
        assert_ne!(&r1[..4], b"2034");
    }

    #[test]
    fn year_9999_boundary_renders_but_year_10000_fails_loud() {
        // 9999-12-31T23:59:59Z is the last honestly-renderable second.
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(format_iso8601_utc(253_402_300_799, &mut r1, &mut r2));
        assert_eq!(&r1[..4], b"9999");
        // 10000-01-01T00:00:00Z is the first that cannot.
        let mut r1b = [b' '; DISPLAY_COLS];
        let mut r2b = [b' '; DISPLAY_COLS];
        assert!(!format_iso8601_utc(253_402_300_800, &mut r1b, &mut r2b));
    }

    #[test]
    fn ordinary_dates_still_render_unchanged() {
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        // 2024-01-01T00:00:00Z.
        assert!(format_iso8601_utc(1_704_067_200, &mut r1, &mut r2));
        assert_eq!(&r1[..10], b"2024-01-01");
        assert_eq!(&r2[..9], b"00:00:00 ");
    }
}

#[cfg(test)]
mod faithless_formatter_fixed {
    //! REGRESSION (audit 2026-06-26 — faithless-formatter class).
    //!
    //! `render_chain_id` and `render_token_ticker` discarded `field.path` and
    //! rendered an envelope / param value instead of the field's signed word,
    //! while dbgen's completeness lint (`check_*_field_completeness`) credited
    //! the field as covering its ABI word — a display != signed gap primed to
    //! fire the moment a `chainId` / `tokenTicker` descriptor shipped (e.g. a
    //! cross-chain bridge's destination chain). Both now resolve `field.path`
    //! and render THAT word; `tokenTicker` additionally shows the token
    //! identity (full address) when no Merkle-verified ticker is bound.
    use super::*;
    use crate::abi::container_field;
    use crate::ir::{ContextKind, Erc7730Ir};
    use std::format;

    /// Build a throwaway `Erc7730Ir` whose `pool` holds a single compiled path
    /// program at offset 1 (mirrors `walker_slot_confusion_fixed::ir_with_path`).
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
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

    /// `RootStructured` path program reading head word `slot`.
    fn slot_prog(slot: u16) -> [u8; 4] {
        [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            (slot >> 8) as u8,
            slot as u8,
        ]
    }

    fn container_prog(field: u16) -> [u8; 4] {
        [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (field >> 8) as u8,
            field as u8,
        ]
    }

    fn envelope_chain(chain_id: u64) -> ContractContainerCtx {
        ContractContainerCtx::outer(chain_id, [0u8; 20], U256::zero(), 0, None)
    }

    fn envelope_chain_with_sender(chain_id: u64, sender: [u8; 20]) -> ContractContainerCtx {
        ContractContainerCtx::outer(chain_id, [0u8; 20], U256::zero(), 0, Some(sender))
    }

    fn field(op: FormatOp) -> FieldEntry<'static> {
        FieldEntry {
            format_op: op as u8,
            label: b"Dest",
            path_off: 1,
            param_off: 0,
        }
    }

    #[test]
    fn chain_id_renders_field_word_not_envelope() {
        // Field path -> head word 0 = 8453 (Base); envelope chain = 1 (Mainnet).
        // The faithful formatter must show the SIGNED 8453, not the envelope 1.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        body[24..32].copy_from_slice(&8453u64.to_be_bytes());
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx).expect("renders");
        assert_eq!(
            &pages.buf[0][1][..4],
            b"8453",
            "shows the field's signed chain id"
        );
        assert_eq!(
            &pages.buf[0][2][..6],
            b"(Base)",
            "names the field's chain, not the envelope"
        );
        // The pre-fix lie was the envelope chain (1 / Mainnet).
        assert_ne!(&pages.buf[0][2][..9], b"(Mainnet)");
    }

    #[test]
    fn chain_id_container_root_still_shows_envelope() {
        // `@.chainId` (container root) must keep rendering the context chain.
        let prog = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (container_field::CHAIN_ID >> 8) as u8,
            container_field::CHAIN_ID as u8,
        ];
        let ir = ir_with_path(&prog);
        let tx = envelope_chain(10); // Optimism
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &[], &tx).expect("renders");
        assert_eq!(&pages.buf[0][1][..2], b"10");
        assert_eq!(&pages.buf[0][2][..10], b"(Optimism)");
    }

    #[test]
    fn from_container_requires_and_renders_bound_userop_sender() {
        let ir = ir_with_path(&container_prog(container_field::FROM));
        let resolver = NameResolver::new();
        let tx = envelope_chain(1);
        let mut absent_pages = Pages::with_len(0);
        assert_eq!(
            render_address_name(
                &field(FormatOp::AddressName),
                &mut absent_pages,
                &ir,
                &[],
                &tx,
                &resolver,
                &ParamSet::default(),
            ),
            Err(RenderErr::Reject("7730 from unbound"))
        );
        assert_eq!(absent_pages.len, 0);

        let sender = [0x11u8; 20];
        let sender_ctx = envelope_chain_with_sender(1, sender);
        let mut pages = Pages::with_len(0);
        render_address_name(
            &field(FormatOp::AddressName),
            &mut pages,
            &ir,
            &[],
            &sender_ctx,
            &resolver,
            &ParamSet::default(),
        )
        .expect("bound @.from renders");
        assert_eq!(&pages.buf[0][1], b"0x11111111111111");
        assert_eq!(&pages.buf[0][2], b"1111111111111111");
        assert_eq!(&pages.buf[0][3][..10], b"1111111111");

        let before = pages.buf;
        for byte in 0..sender.len() {
            let mut changed = sender;
            changed[byte] ^= 1;
            let changed_ctx = envelope_chain_with_sender(1, changed);
            let mut changed_pages = Pages::with_len(0);
            render_address_name(
                &field(FormatOp::AddressName),
                &mut changed_pages,
                &ir,
                &[],
                &changed_ctx,
                &resolver,
                &ParamSet::default(),
            )
            .expect("changed @.from renders");
            assert_ne!(
                before, changed_pages.buf,
                "flipping sender byte {byte} must change the rendered pages"
            );
        }
    }

    #[test]
    fn raw_from_is_an_exact_zero_padded_abi_address_word() {
        let ir = ir_with_path(&container_prog(container_field::FROM));
        let sender = [0x22u8; 20];
        let sender_ctx = envelope_chain_with_sender(1, sender);
        let mut pages = Pages::with_len(0);
        render_raw(
            &field(FormatOp::Raw),
            &mut pages,
            &ir,
            &[],
            &sender_ctx,
            &ParamSet::default(),
        )
        .expect("raw @.from renders");
        assert_eq!(pages.len, 2);
        assert_eq!(&pages.buf[0][1], b"0000000000000000");
        assert_eq!(&pages.buf[0][2], b"0000000022222222");
        assert_eq!(&pages.buf[1][1], b"2222222222222222");
        assert_eq!(&pages.buf[1][2], b"2222222222222222");
    }

    #[test]
    fn chain_id_above_u64_falls_back_to_full_raw_word() {
        // A >u64 word can't name a real chain; never render a truncated value.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        body[0] = 1; // high byte set -> > u64
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx).expect("renders");
        assert_eq!(pages.as_slice().len(), 2);
        assert_eq!(&pages.buf[0][1], b"0100000000000000");
        assert_eq!(&pages.buf[1][2], b"0000000000000000");
    }

    #[test]
    fn chain_id_seventeen_digits_within_u64_falls_back_to_full_raw_word() {
        // A 17-digit chain id is <= u64 but cannot fit a 16-col row in full;
        // `write_decimal_into` would silently drop its low digit, painting a
        // different (smaller) chain number than the one signed. Fail loud.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        // 12_345_678_901_234_567 = 17 digits, < u64::MAX.
        body[24..32].copy_from_slice(&12_345_678_901_234_567u64.to_be_bytes());
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx).expect("renders");
        assert_eq!(pages.as_slice().len(), 2);
        let expected = format!("{:016x}", 12_345_678_901_234_567u64);
        assert_eq!(&pages.buf[1][2], expected.as_bytes());
    }

    #[test]
    fn token_ticker_unbound_shows_address_not_unknown() {
        // Field path -> head word 0 = token address; no erc20 metadata bound.
        // The faithful formatter must show the address (token identity), not
        // the old "(unknown token)" that hid the signed operand.
        let ir = ir_with_path(&slot_prog(0));
        let token = [0xABu8; 20];
        let mut body = [0u8; 32];
        body[12..32].copy_from_slice(&token);
        let tx = envelope_chain(1);
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        render_token_ticker(
            &field(FormatOp::TokenTicker),
            &mut pages,
            &ir,
            &body,
            &tx,
            None,
            &resolver,
            &params,
        )
        .expect("renders");
        // Full address shown: write_addr_full_or_name paints "0x" + hex on r1.
        // (Case-insensitive: the hex is EIP-55 checksummed — its casing is
        // verified by `eip55_tests`; here we only assert the operand is shown.)
        assert_eq!(&pages.buf[0][1][..2], b"0x");
        assert_eq!(
            pages.buf[0][1][2].to_ascii_lowercase(),
            b'a',
            "first nibble of 0xAB"
        );
        assert_eq!(pages.buf[0][1][3].to_ascii_lowercase(), b'b');
        // The pre-fix hid the operand behind this literal.
        assert_ne!(&pages.buf[0][1][..15], b"(unknown token)");
    }

    #[test]
    fn token_ticker_bound_shows_symbol() {
        let ir = ir_with_path(&slot_prog(0));
        let token = [0xCDu8; 20];
        let mut body = [0u8; 32];
        body[12..32].copy_from_slice(&token);
        let tx = envelope_chain(1);
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: token,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        render_token_ticker(
            &field(FormatOp::TokenTicker),
            &mut pages,
            &ir,
            &body,
            &tx,
            Some(&meta),
            &resolver,
            &params,
        )
        .expect("renders");
        assert_eq!(pages.len, 2);
        assert_eq!(&pages.buf[0][1][..4], b"USDC");
        assert_eq!(&pages.buf[1][0][..14], b"Token contract");
        assert_eq!(&pages.buf[1][1][..2], b"0x");
    }

    #[test]
    fn token_ticker_same_symbol_differs_by_full_contract_page() {
        let ir = ir_with_path(&slot_prog(0));
        let tx = envelope_chain(1);
        let resolver = NameResolver::new();
        let params = ParamSet::default();

        let render = |token: [u8; 20]| {
            let mut body = [0u8; 32];
            body[12..32].copy_from_slice(&token);
            let meta = Erc20Metadata {
                chain_id: 1,
                contract: token,
                decimals: 6,
                name: b"Same ticker",
                symbol: b"USDT",
            };
            let mut pages = Pages::with_len(0);
            render_token_ticker(
                &field(FormatOp::TokenTicker),
                &mut pages,
                &ir,
                &body,
                &tx,
                Some(&meta),
                &resolver,
                &params,
            )
            .expect("renders");
            pages
        };

        let pages_a = render([0x11; 20]);
        let pages_b = render([0x22; 20]);
        assert_eq!(pages_a.len, 2);
        assert_eq!(pages_b.len, 2);
        assert_eq!(pages_a.as_slice()[0], pages_b.as_slice()[0]);
        assert_ne!(pages_a.as_slice()[1], pages_b.as_slice()[1]);
    }

    #[test]
    fn bound_token_ticker_identity_page_exhaustion_refuses() {
        let ir = ir_with_path(&slot_prog(0));
        let token = [0xCDu8; 20];
        let mut body = [0u8; 32];
        body[12..32].copy_from_slice(&token);
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: token,
            decimals: 6,
            name: b"Tether",
            symbol: b"USDT",
        };
        let mut pages = Pages::with_len(crate::display::MAX_PAGES - 1);
        assert_eq!(
            render_token_ticker(
                &field(FormatOp::TokenTicker),
                &mut pages,
                &ir,
                &body,
                &envelope_chain(1),
                Some(&meta),
                &NameResolver::new(),
                &ParamSet::default(),
            ),
            Err(RenderErr::PageBudget)
        );
    }
}

#[cfg(test)]
mod block_height_magnitude_fixed {
    //! REGRESSION (audit 2026-06-26 — magnitude-hiding class).
    //!
    //! `render_date`'s blockHeight branch rendered the signed u64 block id
    //! with `write_decimal_into`, which silently drops low-order digits once
    //! the 16-col row fills. With the 7-char "block #" prefix only 9 digits
    //! fit, so a >=10-digit deadline rendered as its top 9 digits — e.g.
    //! block 12_345_678_901 painted "block #123456789" (~100x understated),
    //! a far-future authorization expiry the user reads as near while the
    //! signature commits to the full value. Same display != signed
    //! magnitude-hiding class as the date-year u16 truncation (commit
    //! 7df062d3); the blockHeight sibling had no guard. The fix shows the
    //! FULL magnitude (inline while it fits, else label + full number on r2)
    //! and fails loud only for absurd >16-digit values.
    use super::*;
    use crate::ir::{ContextKind, Erc7730Ir};
    use std::format;

    /// Throwaway IR whose `pool` holds one compiled path program at offset 1
    /// (mirrors `faithless_formatter_fixed::ir_with_path`).
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
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

    fn slot0_prog() -> [u8; 4] {
        [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0]
    }

    fn envelope() -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, None)
    }

    fn date_field() -> FieldEntry<'static> {
        FieldEntry {
            format_op: FormatOp::Date as u8,
            label: b"Expiry",
            path_off: 1,
            param_off: 0,
        }
    }

    /// Render a blockHeight `date` field over a signed word = `block`.
    fn render_block(block: u64) -> Pages {
        let ir = ir_with_path(&slot0_prog());
        let mut body = [0u8; 32];
        body[24..32].copy_from_slice(&block.to_be_bytes());
        let tx = envelope();
        let mut params = ParamSet::default();
        params.date_encoding = Some(DATE_ENC_BLOCKHEIGHT);
        let mut pages = Pages::with_len(0);
        render_date(&date_field(), &mut pages, &ir, &body, &tx, &params).expect("renders");
        pages
    }

    #[test]
    fn small_block_height_renders_inline_unchanged() {
        // < 1e9 (9 digits): the unchanged compact form on row 1.
        let pages = render_block(21_000_000);
        assert_eq!(&pages.buf[0][1][..15], b"block #21000000");
    }

    #[test]
    fn nine_digit_block_height_still_inline() {
        // 999_999_999 — the largest height that fits "block #N" on one row.
        let pages = render_block(999_999_999);
        assert_eq!(&pages.buf[0][1][..16], b"block #999999999");
    }

    #[test]
    fn large_block_height_shows_full_magnitude_not_truncated() {
        // The concrete exploit value: 12_345_678_901 (11 digits). The pre-fix
        // code rendered "block #123456789" (top 9 digits, ~100x understated).
        let pages = render_block(12_345_678_901);
        // Row 1 must NOT be the truncated top-9 lie.
        assert_ne!(&pages.buf[0][1][..15], b"block #12345678");
        assert_eq!(&pages.buf[0][1][..13], b"Block height:");
        // The FULL block id appears on row 2.
        assert_eq!(&pages.buf[0][2][..11], b"12345678901");
    }

    #[test]
    fn sixteen_digit_block_height_shows_full_on_row2() {
        // 1_000_000_000_000_000 (16 digits) is the widest value still shown
        // in full on its own 16-col row.
        let pages = render_block(1_000_000_000_000_000);
        assert_eq!(&pages.buf[0][1][..13], b"Block height:");
        assert_eq!(&pages.buf[0][2][..16], b"1000000000000000");
    }

    #[test]
    fn absurd_block_height_falls_back_to_full_raw_word() {
        // >16 digits (>= 1e16 — not a real block height on any chain). Must
        // fail loud, never paint a silently-truncated value.
        let pages = render_block(12_345_678_901_234_567); // 17 digits
        assert_eq!(pages.as_slice().len(), 2);
        let expected = format!("{:016x}", 12_345_678_901_234_567u64);
        assert_eq!(&pages.buf[1][2], expected.as_bytes());
    }
}

#[cfg(test)]
mod encrypted_formatter_declines {
    //! REGRESSION (audit 2026-06-29 — `encrypted` formatter signed-but-not-shown).
    //!
    //! `render_encrypted` used to paint a benign "[ENCRYPTED]" + descriptor
    //! `fallback_label` page and return `Ok(())` WITHOUT resolving the field's
    //! path — so the 32-byte signed operand at that path (recipient / amount /
    //! spender) was committed to the digest but never shown, on a page that
    //! looks like a normal clear-sign confirmation. It was the only formatter
    //! that "succeeds" while hiding a signed value, and because the field is a
    //! normal *visible* field the dbgen H-3 coverage lint credited it as
    //! shown. It now returns `RenderErr::Reject` like `render_enum`, so the
    //! dispatcher hard-refuses UserOp and off-chain typed paths.
    //! `dbgen::parse_format_name` also refuses `format:"encrypted"` at build time.
    use super::*;
    use crate::ir::{ContextKind, Erc7730Ir};

    fn empty_ir() -> Erc7730Ir<'static> {
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool: &[],
            formats: &[],
            raw: &[],
        }
    }

    fn envelope() -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, None)
    }

    /// `render_encrypted` must REJECT — never emit a confirmable page — even
    /// when a `fallback_label` is present (the worst case: the descriptor
    /// supplies a plausible benign label the old code would have shown).
    #[test]
    fn render_encrypted_refuses_even_with_fallback_label() {
        let mut params = ParamSet::default();
        params.fallback_label = Some(b"Recipient address");
        let field = FieldEntry {
            format_op: FormatOp::Encrypted as u8,
            label: b"Recipient",
            path_off: 0,
            param_off: 0,
        };
        let mut pages = Pages::with_len(0);
        let r = render_encrypted(&field, &mut pages, &params);
        assert!(
            matches!(r, Err(RenderErr::Reject("7730 encrypted field"))),
            "encrypted formatter must refuse, got {r:?}"
        );
        // No page may be produced — a confirmable "[ENCRYPTED]" page is exactly
        // the signed-but-not-shown surface this fix removes.
        assert_eq!(pages.len, 0, "encrypted field must not emit a page");
    }

    /// Routed through `dispatch`, a `FormatOp::Encrypted` field aborts the
    /// whole descriptor render and signing request — it can never produce a
    /// benign clear-sign page or downgrade that hides the operand.
    #[test]
    fn dispatch_encrypted_aborts_render() {
        let ir = empty_ir();
        let tx = envelope();
        let body = [0u8; 32];
        let resolver = pqsigner_tx::names::NameResolver::new();
        let params = ParamSet::default();
        let field = FieldEntry {
            format_op: FormatOp::Encrypted as u8,
            label: b"amount",
            path_off: 0,
            param_off: 0,
        };
        let mut pages = Pages::with_len(0);
        let r = dispatch(
            &field, &mut pages, &ir, &body, &tx, None, &resolver, &params,
        );
        assert!(
            r.is_err(),
            "encrypted field must abort the descriptor render"
        );
        assert_eq!(
            pages.len, 0,
            "no page may be emitted for an encrypted field"
        );
    }
}

#[cfg(kani)]
mod kani_harness {
    //! Tier-P0 formatter ∀ proofs (FV frontier Track 2 M3, 2026-07-04).
    //!
    //! Division-free WYSIWYS properties of the per-`FormatOp` renderers,
    //! proven for ALL inputs (bounded only where stated). Style follows
    //! `render/resolve.rs`: every ∀ harness has a concrete non-vacuity
    //! witness, and the load-bearing ones are pinned by
    //! `scripts/kani_mutations.json` entries (mutation → hand-verified
    //! `VERIFICATION:- FAILED`).
    //!
    //! The `Pages` buffer is CONCRETE (`Pages::with_len(0)`) in the value
    //! harnesses — a fully-symbolic `Pages` is 1.8 KB of free bits that
    //! only bloats CBMC, and the property under proof is about the VALUE
    //! bytes. The always-reject pair instead takes a symbolic `Pages`
    //! because "pages untouched" IS the property there.

    use super::*;
    use crate::display::{DISPLAY_ROWS, MAX_PAGES};
    use crate::ir::{ContextKind, Erc7730Ir};
    use pqsigner_tx::names::NameResolver;

    /// Independent hex oracle: a LOOKUP TABLE, deliberately not the code's
    /// arithmetic `hex_nibble`.
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

    /// Pool: offset-0 filler, then a compiled `RootStructured + FieldIdx(0)`
    /// program (len byte + 4 program bytes) at `path_off = 1` — the resolved
    /// word is exactly `body[0..32]`.
    const SLOT0_POOL: [u8; 6] = [
        0x00,
        4,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0x00,
        0x00,
    ];

    fn mk_ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
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

    fn envelope() -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, None)
    }

    fn mk_field(op: u8, path_off: u16) -> FieldEntry<'static> {
        FieldEntry {
            format_op: op,
            label: b"Field",
            path_off,
            param_off: 0,
        }
    }

    /// Numeric big-endian `a >= b` — the independent order oracle (an
    /// explicit most-significant-byte-first scan, NOT the code's array
    /// `PartialOrd`).
    fn be_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut i = 0usize;
        while i < 32 {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    // ─────────────────────────────────────────────────────────────────
    // 1. Always-Reject pair: `encrypted` + nested `calldata`
    // ─────────────────────────────────────────────────────────────────

    /// ∀ field / params / pages-state: `render_encrypted` REJECTS with the
    /// pinned reason and leaves the `Pages` bundle untouched (`len` + a
    /// symbolic probe cell). The encrypted formatter's signed-but-not-shown
    /// history (audit 2026-06-29) makes "never paints, never succeeds" the
    /// load-bearing anti-regression property — a formatter that `Ok(())`s
    /// without painting the operand is a hidden-operand clear-sign page.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_encrypted_always_rejects_pages_untouched() {
        let label: [u8; 4] = kani::any();
        let f = FieldEntry {
            format_op: kani::any(),
            label: &label,
            path_off: kani::any(),
            param_off: kani::any(),
        };
        let fallback: [u8; 4] = kani::any();
        let mut params = ParamSet::default();
        if kani::any() {
            params.fallback_label = Some(&fallback);
        }
        let mut pages = Pages {
            buf: kani::any(),
            len: kani::any(),
            // The chrome mask (4d61878a, #751). Symbolic like the rest: these
            // harnesses prove a formatter never reads out of bounds and never
            // shrinks `len`, so the mask must be unconstrained too.
            nav: kani::any(),
        };
        kani::assume(pages.len <= MAX_PAGES);
        let (pi, ri, ci): (usize, usize, usize) = kani::any();
        kani::assume(pi < MAX_PAGES && ri < DISPLAY_ROWS && ci < DISPLAY_COLS);
        let before_len = pages.len;
        let before_cell = pages.buf[pi][ri][ci];
        let r = render_encrypted(&f, &mut pages, &params);
        assert!(matches!(r, Err(RenderErr::Reject("7730 encrypted field"))));
        assert!(pages.len == before_len);
        assert!(pages.buf[pi][ri][ci] == before_cell);
    }

    /// Non-vacuity witness for the encrypted Reject (concrete inputs).
    #[kani::proof]
    #[kani::unwind(4)]
    fn fmt_p0_encrypted_rejects_concrete() {
        let f = mk_field(FormatOp::Encrypted as u8, 0);
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        assert!(render_encrypted(&f, &mut pages, &params).is_err());
        assert!(pages.len == 0);
    }

    /// ∀ field / params / pages-state: the legacy descriptor-only
    /// `calldata` route REJECTS and leaves `Pages` untouched. Enrolled
    /// one-level child rendering is owned by the proof-set entry point; an
    /// embedded inner call is never silently rendered as a benign page.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_calldata_nested_always_rejects_pages_untouched() {
        let label: [u8; 4] = kani::any();
        let f = FieldEntry {
            format_op: kani::any(),
            label: &label,
            path_off: kani::any(),
            param_off: kani::any(),
        };
        let fallback: [u8; 4] = kani::any();
        let mut params = ParamSet::default();
        if kani::any() {
            params.fallback_label = Some(&fallback);
        }
        let mut pages = Pages {
            buf: kani::any(),
            len: kani::any(),
            // The chrome mask (4d61878a, #751). Symbolic like the rest: these
            // harnesses prove a formatter never reads out of bounds and never
            // shrinks `len`, so the mask must be unconstrained too.
            nav: kani::any(),
        };
        kani::assume(pages.len <= MAX_PAGES);
        let (pi, ri, ci): (usize, usize, usize) = kani::any();
        kani::assume(pi < MAX_PAGES && ri < DISPLAY_ROWS && ci < DISPLAY_COLS);
        let before_len = pages.len;
        let before_cell = pages.buf[pi][ri][ci];
        let r = super::super::calldata_nested::render(&f, &mut pages, &params);
        assert!(matches!(
            r,
            Err(RenderErr::Reject("7730 nested proof set required"))
        ));
        assert!(pages.len == before_len);
        assert!(pages.buf[pi][ri][ci] == before_cell);
    }

    /// Non-vacuity witness for the legacy descriptor-only calldata Reject.
    #[kani::proof]
    #[kani::unwind(4)]
    fn fmt_p0_calldata_nested_rejects_concrete() {
        let f = mk_field(FormatOp::Calldata as u8, 0);
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        assert!(super::super::calldata_nested::render(&f, &mut pages, &params).is_err());
        assert!(pages.len == 0);
    }

    // ─────────────────────────────────────────────────────────────────
    // 2. FLAGSHIP: `render_raw` hex-exactness
    // ─────────────────────────────────────────────────────────────────

    /// FLAGSHIP ∀: for EVERY resolved 32-byte word, the Raw formatter
    /// (routed through `dispatch`) paints the word as four 16-hex-char rows
    /// across two pages — `hex(word[0..8])`, `hex(word[8..16])`,
    /// `hex(word[16..24])`, `hex(word[24..32])` — with every nibble bound
    /// to an independent lookup TABLE. Every signed byte is shown, so the
    /// WYSIWYS magnitude-hiding class (finding 1.2 / audit 2026-06-26: a
    /// dropped low half made any value < 2^64 render all-zeros) is closed
    /// ∀, not just at the fixed regression vectors.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_raw_word_hex_exactness() {
        let ir = mk_ir(&SLOT0_POOL);
        let word: [u8; 32] = kani::any();
        let tx = envelope();
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let f = mk_field(FormatOp::Raw as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = dispatch(&f, &mut pages, &ir, &word, &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert!(pages.len == 2);
        let mut k = 0usize;
        while k < 32 {
            let (page, row) = [(0usize, 1usize), (0, 2), (1, 1), (1, 2)][k / 8];
            let col = (k % 8) * 2;
            assert!(pages.buf[page][row][col] == HEX_LOWER[(word[k] >> 4) as usize]);
            assert!(pages.buf[page][row][col + 1] == HEX_LOWER[(word[k] & 0x0f) as usize]);
            k += 1;
        }
        // Honest page-progress footers on both pages.
        assert!(pages.buf[0][3][..10] == *b"1/2 > next");
        assert!(pages.buf[1][3][..10] == *b"2/2 > next");
    }

    /// Non-vacuity witness: the byte pattern `01 23 45 67 89 ab cd ef` ×4
    /// renders each of the four hex rows as EXACTLY "0123456789abcdef".
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_raw_word_hex_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let pat = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut word = [0u8; 32];
        let mut i = 0usize;
        while i < 32 {
            word[i] = pat[i % 8];
            i += 1;
        }
        let tx = envelope();
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let f = mk_field(FormatOp::Raw as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = dispatch(&f, &mut pages, &ir, &word, &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert!(pages.len == 2);
        assert!(pages.buf[0][1] == *b"0123456789abcdef");
        assert!(pages.buf[0][2] == *b"0123456789abcdef");
        assert!(pages.buf[1][1] == *b"0123456789abcdef");
        assert!(pages.buf[1][2] == *b"0123456789abcdef");
    }

    // ─────────────────────────────────────────────────────────────────
    // 3. `render_token_amount` unlimited-approval gate
    // ─────────────────────────────────────────────────────────────────

    /// Descriptor-pinned native-currency sentinel used to make the bound
    /// token arm reachable without ERC-20 Merkle plumbing (the gate itself
    /// is hoisted ABOVE the bound match, so this choice only fixes which
    /// unlimited row-shape is painted).
    const NATIVE_SENTINEL: [u8; 20] = [0xEE; 20];

    /// Concrete materiality proof for the precision search: a value that is
    /// not exact at the friendly six-digit baseline becomes exact at the full
    /// authenticated scale.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_native_amount_prepublication_decision_concrete() {
        let mut inexact_word = [0u8; 32];
        inexact_word[16..].copy_from_slice(&1_000_000_000_000_000_001u128.to_be_bytes());
        let inexact = U256(inexact_word);

        let mut exact_word = [0u8; 32];
        exact_word[16..].copy_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes());
        let exact = U256(exact_word);

        assert!(!amount_is_exact_at_fraction_digits(&inexact, 18, 6));
        assert!(amount_is_exact_at_fraction_digits(&inexact, 18, 18));
        assert!(amount_is_exact_at_fraction_digits(&exact, 18, 6));
        assert!(amount_is_exact_at_fraction_digits(&U256::zero(), 18, 6));
    }

    /// Caller-level integration pin for the ordinary native `amount` sink:
    /// one additional wei must now render exactly rather than collide with the
    /// neighboring six-decimal value.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_native_amount_inexact_refuses_before_publication() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&1_000_000_000_000_000_001u128.to_be_bytes());
        let mut pages = Pages::with_len(0);
        let result = render_amount(
            &mk_field(FormatOp::Amount as u8, 1),
            &mut pages,
            &ir,
            &word,
            &envelope(),
            &ParamSet::default(),
        );
        assert!(result.is_ok());
        assert!(pages.len == 1);
    }

    /// Caller-level twin for a descriptor-pinned native sentinel routed
    /// through `tokenAmount`; the same signed value must render exactly.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_native_token_amount_inexact_refuses_before_publication() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&1_000_000_000_000_000_001u128.to_be_bytes());
        let mut params = ParamSet::default();
        params.token = Some(&NATIVE_SENTINEL);
        params.native_currency_addresses = Some(&NATIVE_SENTINEL);
        let mut pages = Pages::with_len(0);
        let result = render_token_amount(
            &mk_field(FormatOp::TokenAmount as u8, 1),
            &mut pages,
            &ir,
            &word,
            &envelope(),
            None,
            &NameResolver::new(),
            &params,
        );
        assert!(result.is_ok());
        assert!(pages.len == 1);
    }

    fn unlimited_params(threshold: &[u8; 32]) -> ParamSet<'_> {
        let mut p = ParamSet::default();
        p.threshold = Some(threshold);
        p.token = Some(&NATIVE_SENTINEL);
        p.native_currency_addresses = Some(&NATIVE_SENTINEL);
        p
    }

    // HONEST DROP (2026-07-04): the two token-amount forall harnesses
    // (value >= T paints the threshold row; value < T never does) and the
    // below-threshold CONCRETE witness all hit CBMC out-of-memory: kani::assume
    // prunes at SAT time but CBMC unwinds BOTH branches first, and the
    // below-threshold branch contains the full format_decimal path (the
    // documented div10 bit-blast swamp) at this harness's unwind. Per the
    // repo's convergence lesson (one honest attempt), the gate-decision forall
    // belongs to the M4 amount-DECISION factoring (a pure no-division fn —
    // work-todo, formatter-forall track); the painting halves are covered by
    // the boundary Kani witness below (>= short-circuits formatting, so it
    // converges), the `token_amount_below_threshold_renders_amount` HOST test
    // (same asserts, no CBMC), and the Lean format_decimal track (deductive,
    // div10 + extract_digits forall already kernel-proven).
    //
    // UPDATE 2026-07-06: the M4 factoring LANDED — the decision ladder now
    // lives in `super::amount_decision::token_amount_decision` (the exact fn
    // `render_token_amount` consumes) and the dropped foralls are CLOSED over
    // it in `amount_decision::kani_harness`: the doubly-symbolic gate
    // biconditional `amt_dec_unlimited_iff_ge_threshold` (value >= T ⟺ an
    // Unlimited* arm, vs an independent MSB-first oracle), the message-param
    // validation forall `amt_dec_message_param_binding`, the token-identity
    // forall `amt_dec_token_identity_binding` (MEDIUM-1 + M-4 classes) and
    // the native-sentinel precedence forall
    // `amt_dec_native_sentinel_precedence`. The PAINT halves (this file)
    // stay covered exactly as described above.

    /// Boundary witness: `value == threshold` IS unlimited (the `>=` edge —
    /// the exact off-by-one a `>` regression would flip).
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_token_amount_threshold_boundary_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut t = [0u8; 32];
        t[31] = 42;
        let value = t;
        let tx = envelope();
        let resolver = NameResolver::new();
        let params = unlimited_params(&t);
        let f = mk_field(FormatOp::TokenAmount as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_token_amount(&f, &mut pages, &ir, &value, &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert!(pages.buf[0][1] == *b"unlimited ETH   ");
    }

    // ─────────────────────────────────────────────────────────────────
    // 4. Exact overflow fallbacks: date / duration / chain-id
    // ─────────────────────────────────────────────────────────────────

    /// ∀ words whose high 24 bytes are not all-zero (`read_u64_be_tail`
    /// returns `None`): the `date` formatter paints every byte across the
    /// shared two-page raw fallback — never a silently-truncated low-64-bit
    /// timestamp or a value-free overflow marker.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_date_high_bytes_raw_exact() {
        let ir = mk_ir(&SLOT0_POOL);
        let word: [u8; 32] = kani::any();
        let mut any_high = false;
        let mut i = 0usize;
        while i < 24 {
            if word[i] != 0 {
                any_high = true;
            }
            i += 1;
        }
        kani::assume(any_high);
        let tx = envelope();
        let params = ParamSet::default();
        let f = mk_field(FormatOp::Date as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_date(&f, &mut pages, &ir, &word, &tx, &params);
        assert!(r.is_ok());
        assert!(pages.len == 2);
        let k: usize = kani::any();
        kani::assume(k < 32);
        let (page, row) = [(0usize, 1usize), (0, 2), (1, 1), (1, 2)][k / 8];
        let col = (k % 8) * 2;
        assert!(pages.buf[page][row][col] == HEX_LOWER[(word[k] >> 4) as usize]);
        assert!(pages.buf[page][row][col + 1] == HEX_LOWER[(word[k] & 0x0f) as usize]);
        assert!(pages.buf[0][3][..10] == *b"1/2 > next");
        assert!(pages.buf[1][3][..10] == *b"2/2 > next");
    }

    /// Converse witness: an in-range timestamp paints the real date, not
    /// the raw fallback (2024-01-01T00:00:00Z).
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_date_normal_timestamp_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&1_704_067_200u64.to_be_bytes());
        let tx = envelope();
        let params = ParamSet::default();
        let f = mk_field(FormatOp::Date as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_date(&f, &mut pages, &ir, &word, &tx, &params);
        assert!(r.is_ok());
        assert!(pages.buf[0][1][..10] == *b"2024-01-01");
        assert!(pages.buf[0][2][..12] == *b"00:00:00 UTC");
    }

    /// ∀ words with a non-zero high byte: the `duration` formatter paints
    /// every byte across the shared two-page raw fallback, never a truncated
    /// duration or value-free marker.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_duration_high_bytes_raw_exact() {
        let ir = mk_ir(&SLOT0_POOL);
        let word: [u8; 32] = kani::any();
        let mut any_high = false;
        let mut i = 0usize;
        while i < 24 {
            if word[i] != 0 {
                any_high = true;
            }
            i += 1;
        }
        kani::assume(any_high);
        let tx = envelope();
        let f = mk_field(FormatOp::Duration as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_duration(&f, &mut pages, &ir, &word, &tx);
        assert!(r.is_ok());
        assert!(pages.len == 2);
        let k: usize = kani::any();
        kani::assume(k < 32);
        let (page, row) = [(0usize, 1usize), (0, 2), (1, 1), (1, 2)][k / 8];
        let col = (k % 8) * 2;
        assert!(pages.buf[page][row][col] == HEX_LOWER[(word[k] >> 4) as usize]);
        assert!(pages.buf[page][row][col + 1] == HEX_LOWER[(word[k] & 0x0f) as usize]);
        assert!(pages.buf[0][3][..10] == *b"1/2 > next");
        assert!(pages.buf[1][3][..10] == *b"2/2 > next");
    }

    /// Converse witness: 90061 s renders "1d 1h 1m 1s", not the raw fallback.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_duration_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&90_061u64.to_be_bytes());
        let tx = envelope();
        let f = mk_field(FormatOp::Duration as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_duration(&f, &mut pages, &ir, &word, &tx);
        assert!(r.is_ok());
        assert!(pages.buf[0][1][..11] == *b"1d 1h 1m 1s");
    }

    // HONEST DROP (2026-07-04): the chain-id forall harness TIMED OUT twice
    // (1500 s, 2400 s) — the chain-NAME lookup layered on the guard is past
    // CBMC's budget. Its load-bearing half — the `read_u64_be_tail` high-bytes
    // guard NEVER silently truncating — is forall-proven TWICE over the SAME
    // shared helper by `fmt_p0_date_high_bytes_raw_exact` and
    // `fmt_p0_duration_high_bytes_raw_exact` (render_chain_id calls the
    // identical guard at its top). The concrete witness below pins the
    // chain-id integration of that guard.

    /// Witness: chain id 8453 renders "8453" + "(Base)" (from the existing
    /// faithless-formatter regression vector).
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_chain_id_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&8453u64.to_be_bytes());
        let tx = envelope();
        let f = mk_field(FormatOp::ChainId as u8, 1);
        let mut pages = Pages::with_len(0);
        let r = render_chain_id(&f, &mut pages, &ir, &word, &tx);
        assert!(r.is_ok());
        assert!(pages.buf[0][1][..4] == *b"8453");
        assert!(pages.buf[0][2][..6] == *b"(Base)");
    }

    // ─────────────────────────────────────────────────────────────────
    // 6. const / enum-label chunking
    // ─────────────────────────────────────────────────────────────────

    /// Build the enum-harness pool: path blob at offset 1, a one-entry enum
    /// table at offset 6 (key = 0), label length + bytes symbolic. Returns
    /// nothing — fills `pool[..16]` in place.
    fn fill_enum_pool_header(pool: &mut [u8]) {
        pool[1] = 4;
        pool[2] = PathOp::RootStructured as u8;
        pool[3] = PathOp::FieldIdx as u8;
        // pool[4..6] = FieldIdx(0); pool[7..15] = key 0 (already zero)
        pool[6] = 1; // entry count
    }

    // HONEST DROP (2026-07-04): the enum-label forall harnesses (lookup plus
    // chunk binding / >3-row rejection) timed out. The lookup primitive has
    // its own proofs in render/enums.rs; the concrete 18-byte witness below
    // pins integration, and a host regression test separately pins the
    // formatter's 49-byte rejection. `render_const` is not equivalent: it now
    // paginates long values instead of sharing the enum's 48-byte ceiling.

    /// Witness: an 18-char label chunks as row1 = first 16, row2 = last 2 +
    /// padding, row3 blank.
    #[kani::proof]
    #[kani::unwind(52)]
    fn fmt_p0_enum_label_chunks_concrete() {
        const LMAX: usize = 48;
        let mut pool = [0u8; 16 + LMAX];
        fill_enum_pool_header(&mut pool);
        let text = b"ABCDEFGHIJKLMNOPQR"; // 18 chars
        pool[15] = text.len() as u8;
        pool[16..16 + text.len()].copy_from_slice(text);
        let ir = mk_ir(&pool);
        let tx = envelope();
        let mut params = ParamSet::default();
        params.enum_ref = Some(6);
        let f = mk_field(FormatOp::Enum as u8, 1);
        let body = [0u8; 32];
        let mut pages = Pages::with_len(0);
        let r = render_enum(&f, &mut pages, &ir, &body, &tx, &params);
        assert!(r.is_ok());
        assert!(pages.buf[0][1] == *b"ABCDEFGHIJKLMNOP");
        assert!(pages.buf[0][2] == *b"QR              ");
        assert!(pages.buf[0][3] == [b' '; DISPLAY_COLS]);
    }

    /// ∀ canonical const-annotation values (1..=48 printable bytes, no trailing
    /// display-padding space): `dispatch` accepts only the canonical Raw/no-path
    /// shape and rows 1-3 show the descriptor-pinned string byte-exact and
    /// space-padded.
    ///
    /// Every backing byte is constrained printable, including the suffix past
    /// `clen`. Every canonical prefix has such an extension; a single symbolic
    /// display index then proves all 48 positions without a second symbolic
    /// 48-iteration assertion loop. The bounded campaign remains an explicit
    /// no-verdict timeout until it converges.
    ///
    /// Compiled out of `make kani` behind `kani-nonterminating` (#776): every
    /// nightly that reached it (2026-09-06, -16, -29 checked) was cancelled
    /// hours inside it, which also suppressed every later crate in the job.
    #[cfg(feature = "kani-nonterminating")]
    #[kani::proof]
    #[kani::unwind(52)]
    fn fmt_p0_const_value_chunks_bind_rows() {
        const CMAX: usize = 48;
        let backing: [u8; CMAX] = kani::any();
        let clen: usize = kani::any();
        kani::assume(clen > 0 && clen <= CMAX);
        let mut i = 0usize;
        while i < CMAX {
            kani::assume((0x20..0x7f).contains(&backing[i]));
            i += 1;
        }
        kani::assume(backing[clen - 1] != b' ');
        let ir = mk_ir(&SLOT0_POOL);
        let tx = envelope();
        let resolver = NameResolver::new();
        let mut params = ParamSet::default();
        params.const_value = Some(&backing[..clen]);
        let f = mk_field(FormatOp::Raw as u8, 0);
        let mut pages = Pages::with_len(0);
        let r = dispatch(&f, &mut pages, &ir, &[], &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert!(pages.len == 1);
        let k: usize = kani::any();
        kani::assume(k < CMAX);
        let expected = if k < clen { backing[k] } else { b' ' };
        assert!(pages.buf[0][1 + k / DISPLAY_COLS][k % DISPLAY_COLS] == expected);
    }

    /// Witness: a 20-char const value chunks across rows 1-2.
    #[kani::proof]
    #[kani::unwind(52)]
    fn fmt_p0_const_value_chunks_concrete() {
        let ir = mk_ir(&SLOT0_POOL);
        let tx = envelope();
        let resolver = NameResolver::new();
        let mut params = ParamSet::default();
        params.const_value = Some(b"Vault share (ERC4626");
        let f = mk_field(FormatOp::Raw as u8, 0);
        let mut pages = Pages::with_len(0);
        let r = dispatch(&f, &mut pages, &ir, &[], &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert!(pages.buf[0][1] == *b"Vault share (ERC");
        assert!(pages.buf[0][2] == *b"4626            ");
        assert!(pages.buf[0][3] == [b' '; DISPLAY_COLS]);
    }

    /// Two distinct accepted one-byte preimages cannot paint the same trusted
    /// display transcript. This is the smallest universal injectivity harness;
    /// host boundary tests cover multi-page chunking and exact-length framing.
    #[kani::proof]
    #[kani::unwind(34)]
    fn fmt_p0_eip712_string_one_byte_is_injective() {
        let left: u8 = kani::any();
        let right: u8 = kani::any();
        kani::assume((0x20..0x7f).contains(&left));
        kani::assume((0x20..0x7f).contains(&right));
        kani::assume(left != right);

        let field = mk_field(FormatOp::Raw as u8, 1);
        let mut left_pages = Pages::with_len(0);
        let mut right_pages = Pages::with_len(0);
        assert!(render_eip712_string_preimage(&field, &mut left_pages, &[left]).is_ok());
        assert!(render_eip712_string_preimage(&field, &mut right_pages, &[right]).is_ok());
        assert!(left_pages.as_slice() != right_pages.as_slice());
    }
}

#[cfg(test)]
mod token_amount_threshold_host_tests {
    //! HOST replacements for the token-amount Kani harnesses that hit CBMC
    //! out-of-memory (see the HONEST DROP note in `kani_harness`): the
    //! below-threshold arm formats the amount (the documented div10
    //! bit-blast swamp), so its witnesses run here — same asserts, no CBMC.
    //! The ∀ gate-decision proof landed with the M4 amount-decision
    //! factoring (2026-07-06) — see `super::amount_decision::kani_harness`;
    //! these tests keep pinning the PAINT integration of the decision.
    use super::*;
    use crate::ir::{ContextKind, Erc7730Ir};
    use pqsigner_tx::names::NameResolver;

    const SLOT0_POOL: [u8; 6] = [
        0x00,
        4,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0x00,
        0x00,
    ];
    const NATIVE_SENTINEL: [u8; 20] = [0xEE; 20];

    fn mk_ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
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

    fn envelope() -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, None)
    }

    fn unlimited_params(threshold: &[u8; 32]) -> ParamSet<'_> {
        let mut p = ParamSet::default();
        p.threshold = Some(threshold);
        p.token = Some(&NATIVE_SENTINEL);
        p.native_currency_addresses = Some(&NATIVE_SENTINEL);
        p
    }

    fn field() -> FieldEntry<'static> {
        FieldEntry {
            format_op: FormatOp::TokenAmount as u8,
            label: b"Field",
            path_off: 1,
            param_off: 0,
        }
    }

    /// value < threshold ⇒ the AMOUNT renders (never the threshold row).
    #[test]
    fn token_amount_below_threshold_renders_amount() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut value = [0u8; 32];
        value[24..32].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
        let mut threshold = [0u8; 32];
        threshold[24..32].copy_from_slice(&2_000_000_000_000_000_000u64.to_be_bytes());
        let tx = envelope();
        let resolver = NameResolver::new();
        let params = unlimited_params(&threshold);
        let f = field();
        let mut pages = Pages::with_len(0);
        let r = render_token_amount(&f, &mut pages, &ir, &value, &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert_eq!(pages.len, 1);
        assert_eq!(&pages.buf[0][1][..5], b"1 ETH");
        assert_eq!(&pages.buf[0][3][..6], b"> next");
        assert_ne!(&pages.buf[0][1][..10], b"unlimited ");
    }

    /// One exactly displayable quantum below the boundary stays an amount; AT
    /// the boundary the threshold row paints (the Kani boundary witness proves
    /// the == case). A one-wei-below vector now correctly refuses under the
    /// native exactness contract, so use the smallest six-decimal quantum.
    #[test]
    fn token_amount_one_display_quantum_below_boundary_still_amount() {
        let ir = mk_ir(&SLOT0_POOL);
        let mut threshold = [0u8; 32];
        threshold[16..].copy_from_slice(&2_000_000_000_000_000_000u128.to_be_bytes());
        let mut value = [0u8; 32];
        value[16..].copy_from_slice(&1_999_999_000_000_000_000u128.to_be_bytes());
        let tx = envelope();
        let resolver = NameResolver::new();
        let params = unlimited_params(&threshold);
        let f = field();
        let mut pages = Pages::with_len(0);
        let r = render_token_amount(&f, &mut pages, &ir, &value, &tx, None, &resolver, &params);
        assert!(r.is_ok());
        assert_ne!(&pages.buf[0][1][..10], b"unlimited ");
    }
}

#[cfg(test)]
mod adversarial_renderer_regressions {
    use super::*;
    use crate::ir::{ContextKind, Erc7730Ir};
    use crate::render::params::{DYNAMIC_KIND_BYTES, DYNAMIC_KIND_STRING};
    use pqsigner_tx::names::NameMeta;

    const DYNAMIC_POOL: [u8; 7] = [
        0,
        5,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0,
        0,
        PathOp::FollowOffset as u8,
    ];
    const SLOT_POOL: [u8; 6] = [
        0,
        4,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0,
        0,
    ];
    // RootStructured + FieldIdx(0x0025) + ArrayAll. The 0x25 is an OPERAND,
    // not a FollowOffset opcode; byte-search-based multi detection gets this
    // wrong and weakens the array tail-placement gate.
    const ARRAY_OPERAND_25_POOL: [u8; 7] = [
        0,
        5,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0,
        PathOp::FollowOffset as u8,
        PathOp::ArrayAll as u8,
    ];
    const ARRAY_MULTI_POOL: [u8; 8] = [
        0,
        6,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0,
        0,
        PathOp::FollowOffset as u8,
        PathOp::ArrayAll as u8,
    ];
    const SOLE_ARRAY_POOL: [u8; 7] = [
        0,
        5,
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        0,
        0,
        PathOp::ArrayAll as u8,
    ];
    const SIGNED_TOKEN_PATH: [u8; 4] = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 1];

    fn ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: crate::ir::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0; 20],
            descriptor_hash: [0; 32],
            domain_separator: [0; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    fn tx() -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, None)
    }

    fn tx_with_sender(sender: [u8; 20]) -> ContractContainerCtx {
        ContractContainerCtx::outer(1, [0u8; 20], U256::zero(), 0, Some(sender))
    }

    fn guarded_pool(path: &[u8], mode: u8, expected: [u8; 32]) -> std::vec::Vec<u8> {
        use crate::render::params::{PARAM_INTEGER_WIDTH, PARAM_TERMINAL_KIND, PARAM_WORD_GUARD};
        let mut body = std::vec![PARAM_WORD_GUARD, 33, mode];
        body.extend_from_slice(&expected);
        body.extend_from_slice(&[
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::Unsigned as u8,
            PARAM_INTEGER_WIDTH,
            1,
            32,
        ]);
        let mut pool = std::vec![0, path.len() as u8];
        pool.extend_from_slice(&path);
        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);
        pool
    }

    #[test]
    fn sender_address_substitution_is_exact_and_requires_the_bound_signer() {
        static SENTINEL: [u8; 20] = {
            let mut value = [0u8; 20];
            value[19] = 1;
            value
        };
        let signer = [0xABu8; 20];
        let mut body = [0u8; 32];
        body[12..].copy_from_slice(&SENTINEL);
        let mut params = ParamSet::default();
        params.sender_addresses = Some(&SENTINEL);

        let mut pages = Pages::with_len(0);
        render_address_name(
            &field(FormatOp::AddressName as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &body,
            &tx_with_sender(signer),
            &NameResolver::new(),
            &params,
        )
        .expect("exact sentinel substitutes");
        let mut expected_r1 = [b' '; DISPLAY_COLS];
        let mut expected_r2 = [b' '; DISPLAY_COLS];
        let mut expected_r3 = [b' '; DISPLAY_COLS];
        write_addr_full(
            &mut expected_r1,
            &mut expected_r2,
            &mut expected_r3,
            &signer,
        );
        assert_eq!(pages.buf[0][1], expected_r1);
        assert_eq!(pages.buf[0][2], expected_r2);
        assert_eq!(pages.buf[0][3], expected_r3);

        let mut no_signer_pages = Pages::with_len(0);
        assert_eq!(
            render_address_name(
                &field(FormatOp::AddressName as u8, 1),
                &mut no_signer_pages,
                &ir(&SLOT_POOL),
                &body,
                &tx(),
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::Reject("7730 sender unbound"))
        );
        assert_eq!(no_signer_pages.len, 0);

        body[31] = 3;
        let mut near_pages = Pages::with_len(0);
        render_address_name(
            &field(FormatOp::AddressName as u8, 1),
            &mut near_pages,
            &ir(&SLOT_POOL),
            &body,
            &tx(),
            &NameResolver::new(),
            &params,
        )
        .expect("near sentinel remains literal");
        assert_ne!(near_pages.buf[0][1], expected_r1);
    }

    #[test]
    fn word_guard_preflight_enforces_structured_and_outer_value_words() {
        use crate::render::params::{WORD_GUARD_EQ, WORD_GUARD_NE};

        let structured = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
        let mut forbidden = [0u8; 32];
        forbidden[31] = 2;
        let pool = guarded_pool(&structured, WORD_GUARD_NE, forbidden);
        let fields = one_field_bytes(FormatOp::Amount as u8, 1, 6);
        let fmt = format(&fields, 1, 1);
        let descriptor = ir(&pool);
        assert_eq!(
            validate_contract_word_guards(
                &descriptor,
                &fmt,
                &forbidden,
                &forbidden,
                ContractCalldataMode::Standard,
                &tx(),
            ),
            Err(RenderErr::Reject("7730 word guard failed"))
        );
        let mut allowed = forbidden;
        allowed[31] = 1;
        assert_eq!(
            validate_contract_word_guards(
                &descriptor,
                &fmt,
                &allowed,
                &allowed,
                ContractCalldataMode::Standard,
                &tx(),
            ),
            Ok(())
        );

        let container_value = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (container_field::VALUE >> 8) as u8,
            container_field::VALUE as u8,
        ];
        let pool = guarded_pool(&container_value, WORD_GUARD_EQ, [0u8; 32]);
        let descriptor = ir(&pool);
        let fields = one_field_bytes(FormatOp::Amount as u8, 1, 6);
        let fmt = format(&fields, 1, 1);
        assert_eq!(
            validate_contract_word_guards(
                &descriptor,
                &fmt,
                &[0u8; 32],
                &[0u8; 32],
                ContractCalldataMode::Standard,
                &tx(),
            ),
            Ok(())
        );
        let mut funded = tx();
        funded.value.0[31] = 1;
        assert_eq!(
            validate_contract_word_guards(
                &descriptor,
                &fmt,
                &[0u8; 32],
                &[0u8; 32],
                ContractCalldataMode::Standard,
                &funded,
            ),
            Err(RenderErr::Reject("7730 word guard failed"))
        );

        let mut eip712_container_descriptor = descriptor;
        eip712_container_descriptor.context_kind = ContextKind::Eip712;
        assert_eq!(
            validate_contract_word_guards(
                &eip712_container_descriptor,
                &fmt,
                &[0u8; 32],
                &[0u8; 32],
                ContractCalldataMode::Standard,
                &tx(),
            ),
            Err(RenderErr::Reject("7730 bad eip712 guard path"))
        );

        let nested = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FieldIdx as u8,
            0,
            0,
        ];
        let pool = guarded_pool(&nested, WORD_GUARD_EQ, [0u8; 32]);
        let mut descriptor = ir(&pool);
        descriptor.context_kind = ContextKind::Eip712;
        let fields = one_field_bytes(FormatOp::Raw as u8, 1, 9);
        let fmt = format(&fields, 1, 1);
        assert_eq!(
            validate_contract_word_guards(
                &descriptor,
                &fmt,
                &[0u8; 32],
                &[0u8; 32],
                ContractCalldataMode::Standard,
                &tx(),
            ),
            Err(RenderErr::Reject("7730 bad eip712 guard path"))
        );
    }

    #[test]
    fn array_multi_detection_parses_opcodes_not_operands() {
        let sole = ir(&ARRAY_OPERAND_25_POOL);
        assert!(path_ends_with_array_all(&sole, 1).unwrap());
        assert!(!array_all_is_multi(&sole, 1).unwrap());

        let multi = ir(&ARRAY_MULTI_POOL);
        assert!(path_ends_with_array_all(&multi, 1).unwrap());
        assert!(array_all_is_multi(&multi, 1).unwrap());
    }

    #[test]
    fn nft_collection_params_require_exactly_one_dedicated_binding() {
        static COLLECTION: [u8; 20] = [0xA4; 20];
        static PATH: [u8; 4] = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (crate::abi::container_field::TO >> 8) as u8,
            crate::abi::container_field::TO as u8,
        ];

        let mut params = ParamSet::default();
        assert!(!nft_params_are_canonical(&params));
        params.nft_collection = Some(&COLLECTION);
        assert!(nft_params_are_canonical(&params));
        params.nft_collection_path = Some(&PATH);
        assert!(!nft_params_are_canonical(&params));
        params.nft_collection = None;
        assert!(nft_params_are_canonical(&params));
        params.token = Some(&COLLECTION);
        assert!(
            !nft_params_are_canonical(&params),
            "cross-formatter token TLV cannot be ignored by nftName"
        );
    }

    #[test]
    fn nft_collection_path_caller_accepts_only_exact_container_to() {
        static STRUCTURED: [u8; 4] = [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];
        static EXACT_TO: [u8; 4] = crate::render::params::NFT_COLLECTION_TO_PATH;

        let mut params = ParamSet::default();
        params.nft_collection_path = Some(&STRUCTURED);
        assert_eq!(
            resolve_nft_collection(&[0u8; 32], &tx(), &params),
            Err(RenderErr::Reject("7730 bad nft collection path"))
        );

        let mut envelope = tx();
        envelope.target = [0xA4; 20];
        params.nft_collection_path = Some(&EXACT_TO);
        assert_eq!(
            resolve_nft_collection(&[0xFFu8; 32], &envelope, &params),
            Ok([0xA4; 20]),
            "@.to must come from the signed envelope, never calldata"
        );
    }

    #[test]
    fn nft_collection_name_never_treats_chain_zero_as_exact() {
        static COLLECTION: [u8; 20] = [0xA4; 20];
        let mut params = ParamSet::default();
        params.nft_collection = Some(&COLLECTION);

        let mut envelope = tx();
        envelope.chain_id = 0;
        let mut resolver = NameResolver::new();
        resolver.push(NameMeta {
            chain_id: 0,
            address: COLLECTION,
            name: b"Wildcard NFT",
        });

        let mut pages = Pages::with_len(0);
        render_nft_name(
            &field(FormatOp::NftName as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &[0u8; 32],
            &envelope,
            &resolver,
            &params,
        )
        .unwrap();
        assert_eq!(&pages.buf[1][0][..14], b"NFT collection");
        assert_ne!(pages.buf[1][0][0], b'+');
    }

    #[test]
    fn enum_label_over_three_rows_is_rejected_not_truncated() {
        const LABEL_LEN: usize = 3 * DISPLAY_COLS + 1;
        let mut pool = [0u8; 16 + LABEL_LEN];
        pool[1] = 4;
        pool[2] = PathOp::RootStructured as u8;
        pool[3] = PathOp::FieldIdx as u8;
        pool[4] = 0;
        pool[5] = 0;
        pool[6] = 1; // one enum entry; key bytes 7..15 remain zero
        pool[15] = LABEL_LEN as u8;
        pool[16..].fill(b'A');

        let ir = ir(&pool);
        let mut params = ParamSet::default();
        params.enum_ref = Some(6);
        let mut pages = Pages::with_len(0);
        let result = render_enum(
            &field(FormatOp::Enum as u8, 1),
            &mut pages,
            &ir,
            &[0u8; 32],
            &tx(),
            &params,
        );
        assert!(matches!(
            result,
            Err(RenderErr::Reject("7730 enum label too long"))
        ));
        assert_eq!(pages.len, 0, "rejection must occur before any partial page");
    }

    #[test]
    fn bool_enum_accepts_only_canonical_zero_and_one_words() {
        // Path at offset 1; enum table at offset 6 with the complete injective
        // bool domain: 0 -> Deny, 1 -> Grant.
        let mut pool = std::vec![0u8; 34];
        pool[1] = 4;
        pool[2] = PathOp::RootStructured as u8;
        pool[3] = PathOp::FieldIdx as u8;
        pool[6] = 2;
        pool[15] = 4;
        pool[16..20].copy_from_slice(b"Deny");
        pool[27] = 1;
        pool[28] = 5;
        pool[29..34].copy_from_slice(b"Grant");

        let ir = ir(&pool);
        let mut params = ParamSet::default();
        params.enum_ref = Some(6);
        params.terminal_kind = Some(crate::render::policy::TerminalKind::Bool);
        let enum_field = field(FormatOp::Enum as u8, 1);

        for (word, expected) in [
            ([0u8; 32], b"Deny".as_slice()),
            (
                {
                    let mut word = [0u8; 32];
                    word[31] = 1;
                    word
                },
                b"Grant".as_slice(),
            ),
        ] {
            let mut pages = Pages::with_len(0);
            render_enum(&enum_field, &mut pages, &ir, &word, &tx(), &params)
                .expect("canonical ABI bool renders");
            assert_eq!(&pages.buf[0][1][..expected.len()], expected);
        }

        let mut noncanonical_two = [0u8; 32];
        noncanonical_two[31] = 2;
        let mut dirty_high_byte = [0u8; 32];
        dirty_high_byte[0] = 1;
        for word in [noncanonical_two, dirty_high_byte] {
            let mut pages = Pages::with_len(0);
            assert_eq!(
                render_enum(&enum_field, &mut pages, &ir, &word, &tx(), &params),
                Err(RenderErr::Reject("7730 noncanonical bool enum"))
            );
            assert_eq!(pages.len, 0, "invalid bool must refuse before publication");
        }
    }

    fn dynamic_body(data: &[u8]) -> std::vec::Vec<u8> {
        let padded = data.len().div_ceil(32) * 32;
        let mut body = std::vec![0u8; 64 + padded];
        body[31] = 32; // head slot 0 -> tail at byte 32
        body[56..64].copy_from_slice(&(data.len() as u64).to_be_bytes());
        body[64..64 + data.len()].copy_from_slice(data);
        body
    }

    fn push_pool_entry(pool: &mut std::vec::Vec<u8>, body: &[u8]) -> u16 {
        let offset = u16::try_from(pool.len()).unwrap();
        pool.push(u8::try_from(body.len()).unwrap());
        pool.extend_from_slice(body);
        offset
    }

    fn push_field_bytes(
        fields: &mut std::vec::Vec<u8>,
        label: &[u8],
        path_off: u16,
        param_off: u16,
    ) {
        fields.push(FormatOp::Raw as u8);
        fields.push(u8::try_from(label.len()).unwrap());
        fields.extend_from_slice(label);
        fields.extend_from_slice(&path_off.to_be_bytes());
        fields.extend_from_slice(&param_off.to_be_bytes());
    }

    fn two_blob_topology_fixture(
        first: &[u8],
        second: &[u8],
    ) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, std::vec::Vec<u8>) {
        use crate::render::calldata_topology::{TAIL_KIND_BLOB, TOPOLOGY_VERSION};
        use crate::render::params::{PARAM_DYNAMIC_KIND, PARAM_DYNAMIC_TAIL_TOPOLOGY};

        let mut pool = std::vec![0];
        let path0 = push_pool_entry(
            &mut pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::FollowOffset as u8,
            ],
        );
        let path1 = push_pool_entry(
            &mut pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                1,
                PathOp::FollowOffset as u8,
            ],
        );
        let topology = [
            TOPOLOGY_VERSION,
            2,
            0,
            0,
            TAIL_KIND_BLOB,
            0,
            1,
            TAIL_KIND_BLOB,
        ];
        let mut first_params = std::vec![PARAM_DYNAMIC_TAIL_TOPOLOGY, topology.len() as u8,];
        first_params.extend_from_slice(&topology);
        first_params.extend_from_slice(&[PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING]);
        let first_param = push_pool_entry(&mut pool, &first_params);
        let second_param =
            push_pool_entry(&mut pool, &[PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING]);

        let mut fields = std::vec::Vec::new();
        push_field_bytes(&mut fields, b"First", path0, first_param);
        push_field_bytes(&mut fields, b"Second", path1, second_param);

        let first_padded = first.len().div_ceil(32) * 32;
        let second_padded = second.len().div_ceil(32) * 32;
        let first_start = 64usize;
        let second_start = first_start + 32 + first_padded;
        let mut body = std::vec![0u8; second_start + 32 + second_padded];
        body[24..32].copy_from_slice(&(first_start as u64).to_be_bytes());
        body[56..64].copy_from_slice(&(second_start as u64).to_be_bytes());
        body[first_start + 24..first_start + 32]
            .copy_from_slice(&(first.len() as u64).to_be_bytes());
        body[first_start + 32..first_start + 32 + first.len()].copy_from_slice(first);
        body[second_start + 24..second_start + 32]
            .copy_from_slice(&(second.len() as u64).to_be_bytes());
        body[second_start + 32..second_start + 32 + second.len()].copy_from_slice(second);
        (pool, fields, body)
    }

    fn field(op: u8, path_off: u16) -> FieldEntry<'static> {
        FieldEntry {
            format_op: op,
            label: b"Field",
            path_off,
            param_off: 0,
        }
    }

    fn format<'a>(fields_buf: &'a [u8], field_count: u8, head_words: u16) -> FormatHeader<'a> {
        FormatHeader {
            selector: [0u8; 4],
            field_count,
            static_head_words: head_words,
            nested_descent_count: 0,
            string_preimage_count: 0,
            intent: b"Test",
            type_hash: [0u8; 32],
            fields_buf,
        }
    }

    fn one_field_bytes(op: u8, path_off: u16, param_off: u16) -> std::vec::Vec<u8> {
        let mut out = std::vec![op, 1, b'F'];
        out.extend_from_slice(&path_off.to_be_bytes());
        out.extend_from_slice(&param_off.to_be_bytes());
        out
    }

    fn one_billion_word() -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        word
    }

    fn metadata<'a>(contract: [u8; 20], symbol: &'a [u8]) -> Erc20Metadata<'a> {
        Erc20Metadata {
            chain_id: 1,
            contract,
            decimals: 18,
            name: b"Test token",
            symbol,
        }
    }

    fn word_from_u128(value: u128) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn two_element_array_body(first: [u8; 32], second: [u8; 32]) -> [u8; 128] {
        let mut body = [0u8; 128];
        body[31] = 32; // sole dynamic tail starts after the one-word head
        body[63] = 2; // element count
        body[64..96].copy_from_slice(&first);
        body[96..128].copy_from_slice(&second);
        body
    }

    /// 10^72: divisible by 10^12 (therefore exact at 18 decimals / six
    /// fractional digits) while too wide for the two-row decimal painter.
    fn exact_eighteen_decimal_overflow_word() -> [u8; 32] {
        [
            0x00, 0x00, 0x90, 0xe4, 0x0f, 0xbe, 0xea, 0x1d, 0x3a, 0x4a, 0xbc, 0x89, 0x55, 0xe9,
            0x46, 0xfe, 0x31, 0xcd, 0xcf, 0x66, 0xf6, 0x34, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn sentinel_pages() -> Pages {
        let mut pages = Pages::with_len(1);
        pages.buf[0][0].fill(b'X');
        pages.buf[crate::display::MAX_PAGES - 1][3].fill(b'Z');
        pages
    }

    fn assert_array_high_precision_then_overwide_refuses(
        fmt: FormatOp,
        params: &ParamSet<'_>,
        erc20: Option<&Erc20Metadata<'_>>,
        expected_exact_pages: usize,
    ) {
        let exact = word_from_u128(1_000_000_000_000_000_000);
        let high_precision = word_from_u128(1_000_000_000_000_000_001);

        let exact_body = two_element_array_body(exact, high_precision);
        let mut exact_pages = Pages::with_len(0);
        render_array(
            &field(fmt as u8, 1),
            &mut exact_pages,
            &ir(&SOLE_ARRAY_POOL),
            &exact_body,
            1,
            &tx(),
            erc20,
            &NameResolver::new(),
            params,
        )
        .expect("high-precision scaled array must render exactly");
        assert_eq!(exact_pages.len, expected_exact_pages);

        let overwide_body = two_element_array_body(exact, exact_eighteen_decimal_overflow_word());
        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_array(
                &field(fmt as u8, 1),
                &mut pages,
                &ir(&SOLE_ARRAY_POOL),
                &overwide_body,
                1,
                &tx(),
                erc20,
                &NameResolver::new(),
                params,
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn scalar_unit_widens_exactly_and_rejects_over_capacity_atomically() {
        let mut params = ParamSet::default();
        params.decimals = Some(18);
        params.base = Some(b"shares");

        let exact = word_from_u128(1_000_000_000_000_000_000);
        let mut exact_pages = Pages::with_len(0);
        render_unit(
            &field(FormatOp::Unit as u8, 1),
            &mut exact_pages,
            &ir(&SLOT_POOL),
            &exact,
            &tx(),
            &params,
        )
        .expect("exact unit must render");
        assert_eq!(&exact_pages.buf[0][1][..8], b"1 shares");

        let high_precision = word_from_u128(1_000_000_000_000_000_001);
        let mut high_precision_pages = Pages::with_len(0);
        render_unit(
            &field(FormatOp::Unit as u8, 1),
            &mut high_precision_pages,
            &ir(&SLOT_POOL),
            &high_precision,
            &tx(),
            &params,
        )
        .expect("high-precision unit must render exactly");
        assert_eq!(high_precision_pages.buf[0][1], *b"1.00000000000000");
        assert_eq!(&high_precision_pages.buf[0][2][..11], b"0001 shares");

        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_unit(
                &field(FormatOp::Unit as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &exact_eighteen_decimal_overflow_word(),
                &tx(),
                &params,
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn bound_token_widens_exactly_and_rejects_over_capacity_atomically() {
        let contract = [0x91; 20];
        let meta = metadata(contract, b"TOK");
        let mut params = ParamSet::default();
        params.token = Some(&contract);

        let exact = word_from_u128(1_000_000_000_000_000_000);
        let mut exact_pages = Pages::with_len(0);
        render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut exact_pages,
            &ir(&SLOT_POOL),
            &exact,
            &tx(),
            Some(&meta),
            &NameResolver::new(),
            &params,
        )
        .expect("exact bound token amount must render");
        assert_eq!(&exact_pages.buf[0][1][..5], b"1 TOK");

        let high_precision = word_from_u128(1_000_000_000_000_000_001);
        let mut high_precision_pages = Pages::with_len(0);
        let witness = render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut high_precision_pages,
            &ir(&SLOT_POOL),
            &high_precision,
            &tx(),
            Some(&meta),
            &NameResolver::new(),
            &params,
        )
        .expect("high-precision token amount must render exactly")
        .expect("bound exact amount mints witness");
        assert_eq!(witness.text(), b"1.000000000000000001 TOK");
        assert_eq!(high_precision_pages.buf[0][1], *b"1.00000000000000");
        assert_eq!(&high_precision_pages.buf[0][2][..8], b"0001 TOK");

        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &exact_eighteen_decimal_overflow_word(),
                &tx(),
                Some(&meta),
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn scaled_exactness_amount_array_is_atomic_and_exact_array_accepts() {
        assert_array_high_precision_then_overwide_refuses(
            FormatOp::Amount,
            &ParamSet::default(),
            None,
            3,
        );
    }

    #[test]
    fn narrow_integer_array_padding_is_checked_before_header_publication() {
        let mut params = ParamSet::default();
        params.terminal_kind = Some(TerminalKind::Unsigned);
        params.integer_width_bytes = Some(1);

        let mut one = [0u8; 32];
        one[31] = 1;
        let mut two = [0u8; 32];
        two[31] = 2;
        let canonical = two_element_array_body(one, two);
        let mut canonical_pages = Pages::with_len(0);
        render_array(
            &field(FormatOp::Raw as u8, 1),
            &mut canonical_pages,
            &ir(&SOLE_ARRAY_POOL),
            &canonical,
            1,
            &tx(),
            None,
            &NameResolver::new(),
            &params,
        )
        .expect("canonical uint8 array renders every element");

        let mut dirty_two = two;
        dirty_two[0] = 1;
        let dirty = two_element_array_body(one, dirty_two);
        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_array(
                &field(FormatOp::Raw as u8, 1),
                &mut pages,
                &ir(&SOLE_ARRAY_POOL),
                &dirty,
                1,
                &tx(),
                None,
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::Reject("7730 noncanonical integer"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn scaled_exactness_unit_array_is_atomic_and_exact_array_accepts() {
        let mut params = ParamSet::default();
        params.decimals = Some(18);
        params.base = Some(b"shares");
        assert_array_high_precision_then_overwide_refuses(FormatOp::Unit, &params, None, 3);
    }

    #[test]
    fn scaled_exactness_bound_token_array_is_atomic_and_exact_array_accepts() {
        let contract = [0x92; 20];
        let meta = metadata(contract, b"TOK");
        let mut params = ParamSet::default();
        params.token = Some(&contract);
        assert_array_high_precision_then_overwide_refuses(
            FormatOp::TokenAmount,
            &params,
            Some(&meta),
            4,
        );
    }

    #[test]
    fn scaled_exactness_unverified_raw_and_unlimited_controls_remain_enabled() {
        let contract = [0x93; 20];
        let meta = metadata(contract, b"TOK");
        let inexact = word_from_u128(1_000_000_000_000_000_001);

        // Missing metadata keeps the scalar and array token paths unscaled and
        // exact-as-raw; the scaled exactness preflight must not reject them.
        let mut raw_params = ParamSet::default();
        raw_params.token = Some(&contract);
        let mut scalar_pages = Pages::with_len(0);
        render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut scalar_pages,
            &ir(&SLOT_POOL),
            &inexact,
            &tx(),
            None,
            &NameResolver::new(),
            &raw_params,
        )
        .expect("unverified scalar amount must remain raw");
        assert_eq!(&scalar_pages.buf[0][3][..12], b"! raw, dec=?");

        let raw_array_body = two_element_array_body(inexact, inexact);
        let mut array_pages = Pages::with_len(0);
        render_array(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut array_pages,
            &ir(&SOLE_ARRAY_POOL),
            &raw_array_body,
            1,
            &tx(),
            None,
            &NameResolver::new(),
            &raw_params,
        )
        .expect("unverified array amounts must remain raw");
        assert_eq!(array_pages.len, 4); // header + identity + two raw elements
        assert_eq!(&array_pages.buf[2][3][..12], b"! raw, dec=?");
        assert_eq!(&array_pages.buf[3][3][..12], b"! raw, dec=?");

        // A bound threshold arm paints semantic "unlimited", not a rounded
        // amount, so an otherwise inexact value remains confirmable there.
        let threshold = [0u8; 32];
        let mut unlimited_params = ParamSet::default();
        unlimited_params.token = Some(&contract);
        unlimited_params.threshold = Some(&threshold);
        let mut unlimited_pages = Pages::with_len(0);
        render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut unlimited_pages,
            &ir(&SLOT_POOL),
            &inexact,
            &tx(),
            Some(&meta),
            &NameResolver::new(),
            &unlimited_params,
        )
        .expect("bound unlimited arm must remain semantic");
        assert_eq!(&unlimited_pages.buf[0][1][..9], b"unlimited");
    }

    fn assert_full_contract_page(page: &[[u8; DISPLAY_COLS]; 4], contract: &[u8; 20]) {
        assert_eq!(&page[0][..14], b"Token contract");
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        let mut r3 = [b' '; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, contract);
        assert_eq!(page[1], r1);
        assert_eq!(page[2], r2);
        assert_eq!(page[3], r3);
    }

    #[test]
    fn bound_token_amount_over_capacity_refuses_before_identity_publication() {
        let contract = [0x11; 20];
        let meta = metadata(contract, b"TOK");
        let envelope = tx();
        let resolver = NameResolver::new();
        let mut body = [0u8; 64];
        body[..32].copy_from_slice(&exact_eighteen_decimal_overflow_word());
        body[44..].copy_from_slice(&contract); // token at signed head word 1
        let mut params = ParamSet::default();
        params.token_path = Some(&SIGNED_TOKEN_PATH);
        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &body,
                &envelope,
                Some(&meta),
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn bound_token_amount_same_ticker_always_keeps_exact_contract_identity() {
        let contract_a = [0x21; 20];
        let contract_b = [0x22; 20];
        let meta_a = metadata(contract_a, b"USDT");
        let meta_b = metadata(contract_b, b"USDT");
        let envelope = tx();
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());

        let render = |contract, meta: &Erc20Metadata<'_>| {
            let mut params = ParamSet::default();
            params.token = Some(contract);
            let mut pages = Pages::with_len(0);
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &value,
                &envelope,
                Some(meta),
                &NameResolver::new(),
                &params,
            )
            .unwrap();
            pages
        };

        let pages_a = render(&contract_a, &meta_a);
        let pages_b = render(&contract_b, &meta_b);
        assert_eq!(pages_a.len, 2);
        assert_eq!(pages_b.len, 2);
        assert_eq!(pages_a.as_slice()[0], pages_b.as_slice()[0]);
        assert_ne!(pages_a.as_slice()[1], pages_b.as_slice()[1]);
        assert_full_contract_page(&pages_a.as_slice()[1], &contract_a);
        assert_full_contract_page(&pages_b.as_slice()[1], &contract_b);
    }

    #[test]
    fn bound_token_identity_page_exhaustion_refuses() {
        let contract = [0x23; 20];
        let meta = metadata(contract, b"USDT");
        let mut params = ParamSet::default();
        params.token = Some(&contract);
        let mut pages = Pages::with_len(crate::display::MAX_PAGES - 1);
        assert_eq!(
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &word_from_u128(1_000_000_000_000_000_000),
                &tx(),
                Some(&meta),
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::PageBudget)
        );
    }

    #[test]
    fn dirty_static_token_path_padding_rejects_instead_of_becoming_unnamed_raw() {
        let mut body = [0u8; 64];
        body[31] = 1; // amount at signed head word 0
        body[32] = 1; // dirty high padding in signed token word 1
        body[44..].copy_from_slice(&[0x77; 20]);
        let envelope = tx();
        let mut params = ParamSet::default();
        params.token_path = Some(&SIGNED_TOKEN_PATH);
        let mut pages = Pages::with_len(0);

        assert_eq!(
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &body,
                &envelope,
                None,
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::Reject("7730 tok dirty address"))
        );
        // Resolution happens before any trusted-display page is committed;
        // malformed token identity can never degrade to an unnamed raw amount.
        assert_eq!(pages.len, 0);
    }

    #[test]
    fn unlimited_ticker_suffix_is_never_truncated() {
        let value = [0xff; 32];
        let threshold = [0u8; 32];
        let contract_a = [0x31; 20];
        let contract_b = [0x32; 20];
        let meta_a = metadata(contract_a, b"LONGTOKENA");
        let meta_b = metadata(contract_b, b"LONGTOKENB");
        let envelope = tx();
        let resolver = NameResolver::new();

        let render = |contract, meta: &Erc20Metadata<'_>| {
            let mut params = ParamSet::default();
            params.token = Some(contract);
            params.threshold = Some(&threshold);
            let mut pages = Pages::with_len(0);
            render_token_amount(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &value,
                &envelope,
                Some(meta),
                &resolver,
                &params,
            )
            .unwrap();
            pages
        };

        let pages_a = render(&contract_a, &meta_a);
        let pages_b = render(&contract_b, &meta_b);
        assert_eq!(pages_a.len, 2);
        assert_eq!(pages_b.len, 2);
        assert_eq!(pages_a.buf[0][1], *b"unlimited       ");
        assert_eq!(pages_a.buf[0][2], *b"LONGTOKENA      ");
        assert_eq!(pages_b.buf[0][2], *b"LONGTOKENB      ");
        assert_ne!(pages_a.buf[0], pages_b.buf[0]);
        assert_full_contract_page(&pages_a.buf[1], &contract_a);
        assert_full_contract_page(&pages_b.buf[1], &contract_b);
    }

    #[test]
    fn oversize_unlimited_ticker_uses_exact_contract_identity() {
        let value = [0xff; 32];
        let threshold = [0u8; 32];
        let contract = [0x44; 20];
        let meta = metadata(contract, b"ABCDEFGHIJKLMNOPQ");
        let envelope = tx();
        let mut params = ParamSet::default();
        params.token = Some(&contract);
        params.threshold = Some(&threshold);
        let mut pages = Pages::with_len(0);
        render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &value,
            &envelope,
            Some(&meta),
            &NameResolver::new(),
            &params,
        )
        .unwrap();

        assert_eq!(pages.len, 2);
        assert_eq!(pages.buf[0][1], *b"unlimited       ");
        assert_eq!(pages.buf[0][2], *b"(see token)     ");
        assert_full_contract_page(&pages.buf[1], &contract);
    }

    #[test]
    fn bound_token_amount_array_over_capacity_refuses_before_header_or_identity() {
        let contract = [0x51; 20];
        let meta = metadata(contract, b"TOK");
        let envelope = tx();
        let resolver = NameResolver::new();
        let mut body = [0u8; 96];
        body[31] = 32; // sole dynamic tail starts after the one-word head
        body[63] = 1; // one element
        body[64..].copy_from_slice(&exact_eighteen_decimal_overflow_word());

        let mut params = ParamSet::default();
        params.token = Some(&contract);
        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_array(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SOLE_ARRAY_POOL),
                &body,
                1,
                &envelope,
                Some(&meta),
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn bound_token_amount_array_same_ticker_keeps_exact_contract_identity() {
        let contract_a = [0x61; 20];
        let contract_b = [0x62; 20];
        let meta_a = metadata(contract_a, b"USDT");
        let meta_b = metadata(contract_b, b"USDT");
        let envelope = tx();
        let mut body = [0u8; 96];
        body[31] = 32;
        body[63] = 1;
        body[88..96].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());

        let render = |contract, meta: &Erc20Metadata<'_>| {
            let mut params = ParamSet::default();
            params.token = Some(contract);
            let mut pages = Pages::with_len(0);
            render_array(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SOLE_ARRAY_POOL),
                &body,
                1,
                &envelope,
                Some(meta),
                &NameResolver::new(),
                &params,
            )
            .unwrap();
            pages
        };

        let pages_a = render(&contract_a, &meta_a);
        let pages_b = render(&contract_b, &meta_b);
        assert_eq!(pages_a.len, 3);
        assert_eq!(pages_b.len, 3);
        assert_eq!(pages_a.as_slice()[0], pages_b.as_slice()[0]);
        assert_ne!(pages_a.as_slice()[1], pages_b.as_slice()[1]);
        assert_eq!(pages_a.as_slice()[2], pages_b.as_slice()[2]);
        assert_full_contract_page(&pages_a.as_slice()[1], &contract_a);
        assert_full_contract_page(&pages_b.as_slice()[1], &contract_b);
    }

    #[test]
    fn bound_token_amount_array_identity_page_exhaustion_refuses() {
        let contract = [0x63; 20];
        let meta = metadata(contract, b"USDT");
        let mut body = [0u8; 96];
        body[31] = 32;
        body[63] = 1;
        body[80..96].copy_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes());
        let mut params = ParamSet::default();
        params.token = Some(&contract);
        let mut pages = Pages::with_len(crate::display::MAX_PAGES - 1);
        assert_eq!(
            render_array(
                &field(FormatOp::TokenAmount as u8, 1),
                &mut pages,
                &ir(&SOLE_ARRAY_POOL),
                &body,
                1,
                &tx(),
                Some(&meta),
                &NameResolver::new(),
                &params,
            ),
            Err(RenderErr::PageBudget)
        );
    }

    #[test]
    fn format_preflight_rejects_static_calldata_suffix() {
        let fields = one_field_bytes(FormatOp::Raw as u8, 1, 0);
        let fmt = format(&fields, 1, 1);
        let descriptor = ir(&SLOT_POOL);
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &[0u8; 32], &tx()),
            Ok(ContractCalldataMode::Standard)
        );
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &[0u8; 64], &tx()),
            Err(RenderErr::Reject("7730 static calldata trailing"))
        );
    }

    #[test]
    fn format_preflight_validates_hidden_dynamic_leaf_before_visibility() {
        use crate::render::params::{PARAM_DYNAMIC_KIND, PARAM_VISIBILITY};

        let mut pool = DYNAMIC_POOL.to_vec();
        let param_off = pool.len() as u16;
        // dynamic_kind=string + visibility=never. The framing validator must
        // still consume the path and exact tail before the render loop skips it.
        pool.extend_from_slice(&[
            6,
            PARAM_DYNAMIC_KIND,
            1,
            DYNAMIC_KIND_STRING,
            PARAM_VISIBILITY,
            1,
            crate::ir::Visibility::Never as u8,
        ]);
        let fields = one_field_bytes(FormatOp::Raw as u8, 1, param_off);
        let fmt = format(&fields, 1, 1);
        let descriptor = Erc7730Ir {
            pool: &pool,
            ..ir(&[])
        };
        let canonical = dynamic_body(b"hidden");
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &canonical, &tx()),
            Ok(ContractCalldataMode::Standard)
        );

        let mut dirty = canonical.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &dirty, &tx()),
            Err(RenderErr::Reject("7730 res dirty pad"))
        );
        let mut trailing = canonical;
        trailing.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &trailing, &tx()),
            Err(RenderErr::Reject("7730 res not whole tail"))
        );
    }

    #[test]
    fn format_preflight_accepts_and_renders_two_exact_blob_tails() {
        let (pool, fields, body) = two_blob_topology_fixture(b"alice", b"vienna");
        let descriptor = Erc7730Ir {
            pool: &pool,
            ..ir(&[])
        };
        let fmt = format(&fields, 2, 2);
        let mode = validate_contract_calldata_framing(&descriptor, &fmt, &body, &tx()).unwrap();
        let ContractCalldataMode::MultiTail(partition) = mode else {
            panic!("topology marker did not mint multi-tail authority");
        };
        assert_eq!(partition.len(), 2);

        let resolver = NameResolver::new();
        let mut pages = Pages::with_len(0);
        for field in fmt.fields() {
            let field = field.unwrap();
            let params = parse_params(&descriptor, field.param_off).unwrap();
            render_dynamic_bytes_with_mode(
                &field,
                &mut pages,
                &descriptor,
                &body,
                2,
                mode,
                None,
                &resolver,
                &params,
            )
            .unwrap();
        }
        assert_eq!(pages.len, 2);
        assert_eq!(&pages.buf[0][1][..5], b"alice");
        assert_eq!(&pages.buf[1][1][..6], b"vienna");

        let (_, _, changed) = two_blob_topology_fixture(b"alice", b"berlin");
        let changed_mode =
            validate_contract_calldata_framing(&descriptor, &fmt, &changed, &tx()).unwrap();
        let second = fmt.fields().nth(1).unwrap().unwrap();
        let params = parse_params(&descriptor, second.param_off).unwrap();
        let mut changed_pages = Pages::with_len(0);
        render_dynamic_bytes_with_mode(
            &second,
            &mut changed_pages,
            &descriptor,
            &changed,
            2,
            changed_mode,
            None,
            &resolver,
            &params,
        )
        .unwrap();
        assert_eq!(&changed_pages.buf[0][1][..6], b"berlin");
        assert_ne!(pages.buf[1], changed_pages.buf[0]);
    }

    #[test]
    fn multi_tail_preflight_rejects_alias_gap_padding_suffix_and_unconsumed_tail() {
        let (pool, fields, body) = two_blob_topology_fixture(b"abc", b"z");
        let descriptor = Erc7730Ir {
            pool: &pool,
            ..ir(&[])
        };
        let fmt = format(&fields, 2, 2);

        let mut alias = body.clone();
        alias[56..64].copy_from_slice(&64u64.to_be_bytes());
        assert!(validate_contract_calldata_framing(&descriptor, &fmt, &alias, &tx()).is_err());

        let mut gap = body.clone();
        gap[56..64].copy_from_slice(&160u64.to_be_bytes());
        assert!(validate_contract_calldata_framing(&descriptor, &fmt, &gap, &tx()).is_err());

        let mut dirty_padding = body.clone();
        dirty_padding[64 + 32 + 3] = 1;
        assert!(
            validate_contract_calldata_framing(&descriptor, &fmt, &dirty_padding, &tx()).is_err()
        );

        let mut suffix = body.clone();
        suffix.extend_from_slice(&[0u8; 32]);
        assert!(validate_contract_calldata_framing(&descriptor, &fmt, &suffix, &tx()).is_err());

        let first_field_len = 2 + b"First".len() + 4;
        let one_field = &fields[..first_field_len];
        let incomplete = format(one_field, 1, 2);
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &incomplete, &body, &tx()),
            Err(RenderErr::Reject("7730 topology unconsumed tail"))
        );
    }

    #[test]
    fn format_preflight_rejects_c2_and_relaxed_multi_array_paths() {
        // C2 static member: Root FieldIdx(0) FollowOffset FieldIdx(0).
        let c2_pool = [
            0,
            8,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FollowOffset as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
        ];
        let fields = one_field_bytes(FormatOp::Raw as u8, 1, 0);
        let fmt = format(&fields, 1, 1);
        let c2_ir = ir(&c2_pool);
        let mut c2_body = [0u8; 64];
        c2_body[31] = 32;
        assert_eq!(
            validate_contract_calldata_framing(&c2_ir, &fmt, &c2_body, &tx()),
            Err(RenderErr::Reject("7730 C2 framing unsupported"))
        );

        let multi_ir = ir(&ARRAY_MULTI_POOL);
        let mut multi_body = [0u8; 64];
        multi_body[31] = 32;
        assert_eq!(
            validate_contract_calldata_framing(&multi_ir, &fmt, &multi_body, &tx()),
            Err(RenderErr::Reject("7730 multi-array framing"))
        );
    }

    #[test]
    fn format_preflight_exactly_validates_hidden_dynamic_token_path() {
        use crate::render::params::{PARAM_TOKEN_PATH, PARAM_VISIBILITY};

        let mut pool = SLOT_POOL.to_vec();
        let param_off = pool.len() as u16;
        let token_path = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            1,
            PathOp::FollowOffset as u8,
            PathOp::ArraySlice as u8,
            0,
            0,
            0,
            20,
            0,
        ];
        let param_len = 2 + token_path.len() + 3;
        pool.push(param_len as u8);
        pool.push(PARAM_TOKEN_PATH);
        pool.push(token_path.len() as u8);
        pool.extend_from_slice(&token_path);
        pool.extend_from_slice(&[PARAM_VISIBILITY, 1, crate::ir::Visibility::Never as u8]);

        let fields = one_field_bytes(FormatOp::TokenAmount as u8, 1, param_off);
        let fmt = format(&fields, 1, 2);
        let descriptor = Erc7730Ir {
            pool: &pool,
            ..ir(&[])
        };
        let mut body = std::vec![0u8; 160];
        body[63] = 64; // slot 1 offset == two-word head end
        body[88..96].copy_from_slice(&43u64.to_be_bytes());
        body[96..116].copy_from_slice(&[0x11; 20]);
        body[116..119].copy_from_slice(&[0, 0x0b, 0xb8]);
        body[119..139].copy_from_slice(&[0x22; 20]);
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &body, &tx()),
            Ok(ContractCalldataMode::Standard)
        );

        let mut dirty = body.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &dirty, &tx()),
            Err(RenderErr::Reject("7730 res dirty pad"))
        );
        body.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            validate_contract_calldata_framing(&descriptor, &fmt, &body, &tx()),
            Err(RenderErr::Reject("7730 res not whole tail"))
        );
    }

    #[test]
    fn unknown_chain_amount_without_decimals_paints_exact_raw_integer() {
        let mut envelope = tx();
        envelope.chain_id = 149;
        let mut pages = Pages::with_len(0);
        render_amount(
            &field(FormatOp::Amount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &one_billion_word(),
            &envelope,
            &ParamSet::default(),
        )
        .unwrap();
        assert_eq!(pages.as_slice().len(), 1);
        assert_eq!(&pages.buf[0][1][..10], b"1000000000");
        assert_eq!(&pages.buf[0][3][..12], b"! raw, dec=?");
    }

    #[test]
    fn unknown_chain_native_sentinel_without_decimals_paints_raw() {
        const SENTINEL: [u8; 20] = [0xEE; 20];
        let mut envelope = tx();
        envelope.chain_id = 149;
        let mut params = ParamSet::default();
        params.token = Some(&SENTINEL);
        params.native_currency_addresses = Some(&SENTINEL);
        let mut pages = Pages::with_len(0);
        render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &one_billion_word(),
            &envelope,
            None,
            &NameResolver::new(),
            &params,
        )
        .unwrap();
        assert_eq!(pages.as_slice().len(), 1);
        assert_eq!(&pages.buf[0][1][..10], b"1000000000");
        assert_eq!(&pages.buf[0][3][..12], b"! raw, dec=?");
    }

    #[test]
    fn unknown_chain_array_amount_without_decimals_paints_raw() {
        let mut envelope = tx();
        envelope.chain_id = 149;
        let mut pages = Pages::with_len(0);
        render_array_element(
            &field(FormatOp::Amount as u8, 1),
            FormatOp::Amount,
            &one_billion_word(),
            &mut pages,
            &envelope,
            None,
            None,
            &NameResolver::new(),
            &ParamSet::default(),
        )
        .unwrap();
        assert_eq!(pages.as_slice().len(), 1);
        assert_eq!(&pages.buf[0][1][..10], b"1000000000");
        assert_eq!(&pages.buf[0][3][..12], b"! raw, dec=?");
    }

    #[test]
    fn explicit_decimals_keep_unknown_chain_amount_scaled() {
        let mut envelope = tx();
        envelope.chain_id = 149;
        let mut params = ParamSet::default();
        params.decimals = Some(9);
        let mut pages = Pages::with_len(0);
        render_amount(
            &field(FormatOp::Amount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &one_billion_word(),
            &envelope,
            &params,
        )
        .unwrap();
        assert_eq!(&pages.buf[0][1][..8], b"1 NATIVE");
        assert_eq!(&pages.buf[0][3][..6], b"> next");
    }

    #[test]
    fn ordinary_native_amount_widens_to_exact_adjacent_value() {
        let mut one_eth_one_wei = [0u8; 32];
        one_eth_one_wei[16..].copy_from_slice(&1_000_000_000_000_000_001u128.to_be_bytes());
        let mut pages = Pages::with_len(1);
        pages.buf[0][0][0] = b'X';
        let before_buf = pages.buf;
        let witness = render_amount(
            &field(FormatOp::Amount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &one_eth_one_wei,
            &tx(),
            &ParamSet::default(),
        )
        .expect("one extra wei renders exactly")
        .expect("exact amount mints interpolation witness");
        assert_eq!(witness.text(), b"1.000000000000000001 ETH");
        assert_eq!(pages.len, 2);
        assert_eq!(pages.buf[0], before_buf[0]);
        assert_eq!(pages.buf[1][1], *b"1.00000000000000");
        assert_eq!(&pages.buf[1][2][..8], b"0001 ETH");
    }

    #[test]
    fn native_sentinel_token_amount_widens_to_exact_adjacent_value() {
        const SENTINEL: [u8; 20] = [0xEE; 20];
        let mut one_eth_one_wei = [0u8; 32];
        one_eth_one_wei[16..].copy_from_slice(&1_000_000_000_000_000_001u128.to_be_bytes());
        let mut params = ParamSet::default();
        params.token = Some(&SENTINEL);
        params.native_currency_addresses = Some(&SENTINEL);
        let mut pages = Pages::with_len(1);
        pages.buf[0][0][0] = b'Y';
        let before_buf = pages.buf;
        let witness = render_token_amount(
            &field(FormatOp::TokenAmount as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &one_eth_one_wei,
            &tx(),
            None,
            &NameResolver::new(),
            &params,
        )
        .expect("native-sentinel one extra wei renders exactly")
        .expect("exact native-sentinel amount mints witness");
        assert_eq!(witness.text(), b"1.000000000000000001 ETH");
        assert_eq!(pages.len, 2);
        assert_eq!(pages.buf[0], before_buf[0]);
        assert_eq!(pages.buf[1][1], *b"1.00000000000000");
        assert_eq!(&pages.buf[1][2][..8], b"0001 ETH");
    }

    #[test]
    fn dynamic_bytes_decline_even_when_printable() {
        let mut params = ParamSet::default();
        params.dynamic_kind = Some(DYNAMIC_KIND_BYTES);
        let mut pages = Pages::with_len(0);
        let result = render_dynamic_bytes(
            &field(FormatOp::Raw as u8, 1),
            &mut pages,
            &ir(&DYNAMIC_POOL),
            &dynamic_body(b"same prefix, attacker-controlled suffix"),
            1,
            None,
            &NameResolver::new(),
            &params,
        );
        assert_eq!(result, Err(RenderErr::Reject("7730 opaque bytes")));
        assert_eq!(pages.as_slice().len(), 0);
    }

    #[test]
    fn dynamic_string_cannot_bypass_declared_formatter_or_params() {
        let mut params = ParamSet::default();
        params.dynamic_kind = Some(DYNAMIC_KIND_STRING);
        let body = dynamic_body(b"1000000000000000000");
        let resolver = NameResolver::new();

        let mut amount_pages = Pages::with_len(0);
        assert_eq!(
            render_dynamic_bytes(
                &field(FormatOp::Amount as u8, 1),
                &mut amount_pages,
                &ir(&DYNAMIC_POOL),
                &body,
                1,
                None,
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 dynamic formatter mismatch"))
        );

        params.base = Some(b"ETH");
        let mut param_pages = Pages::with_len(0);
        assert_eq!(
            render_dynamic_bytes(
                &field(FormatOp::Raw as u8, 1),
                &mut param_pages,
                &ir(&DYNAMIC_POOL),
                &body,
                1,
                None,
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 dynamic formatter mismatch"))
        );
    }

    #[test]
    fn dynamic_string_trailing_space_changes_length_row() {
        let mut params = ParamSet::default();
        params.dynamic_kind = Some(DYNAMIC_KIND_STRING);
        let render = |data: &[u8]| {
            let mut pages = Pages::with_len(0);
            render_dynamic_bytes(
                &field(FormatOp::Raw as u8, 1),
                &mut pages,
                &ir(&DYNAMIC_POOL),
                &dynamic_body(data),
                1,
                None,
                &NameResolver::new(),
                &params,
            )
            .unwrap();
            pages
        };
        let plain = render(b"alice");
        let spaced = render(b"alice ");
        assert_ne!(plain.as_slice(), spaced.as_slice());
        assert_eq!(&plain.buf[0][3][..7], b"5 bytes");
        assert_eq!(&spaced.buf[0][3][..7], b"6 bytes");
    }

    fn render_eip712_string(data: &[u8]) -> Result<Pages, RenderErr> {
        let mut pages = Pages::with_len(0);
        render_eip712_string_preimage(&field(FormatOp::Raw as u8, 1), &mut pages, data)?;
        Ok(pages)
    }

    #[test]
    fn eip712_string_painter_covers_zero_one_and_page_boundaries() {
        let empty = render_eip712_string(b"").unwrap();
        assert_eq!(empty.len, 1);
        assert_eq!(&empty.buf[0][1][..7], b"<empty>");
        assert_eq!(&empty.buf[0][3][..11], b"1/1 0 bytes");

        for (len, expected_pages, footer) in [
            (1usize, 1usize, b"1/1 1 bytes".as_slice()),
            (32, 1, b"1/1 32 bytes".as_slice()),
            (33, 2, b"2/2 33 bytes".as_slice()),
            (128, 4, b"4/4 128 bytes".as_slice()),
        ] {
            let data = std::vec![b'x'; len];
            let pages = render_eip712_string(&data).unwrap();
            assert_eq!(pages.len, expected_pages);
            assert_eq!(&pages.buf[expected_pages - 1][3][..footer.len()], footer);
            let mut painted = std::vec::Vec::new();
            for page in &pages.buf[..pages.len] {
                painted.extend_from_slice(&page[1]);
                painted.extend_from_slice(&page[2]);
            }
            assert_eq!(&painted[..len], data.as_slice());
        }
    }

    #[test]
    fn eip712_string_painter_is_injective_for_content_and_trailing_spaces() {
        let alice = render_eip712_string(b"alice").unwrap();
        let alicf = render_eip712_string(b"alicf").unwrap();
        let trailing = render_eip712_string(b"alice ").unwrap();
        assert_ne!(alice.as_slice(), alicf.as_slice());
        assert_ne!(alice.as_slice(), trailing.as_slice());
        assert_eq!(&alice.buf[0][3][..11], b"1/1 5 bytes");
        assert_eq!(&trailing.buf[0][3][..11], b"1/1 6 bytes");
    }

    #[test]
    fn eip712_string_painter_refuses_129_and_non_ascii_without_mutation() {
        for invalid in [
            std::vec![b'x'; EIP712_STRING_PREIMAGE_MAX + 1],
            std::vec![b'\n'],
            std::vec![0x7f],
            std::vec![0x80],
        ] {
            let mut pages = Pages::with_len(1);
            pages.buf[0][0][0] = b'X';
            let before_len = pages.len;
            let before_buf = pages.buf;
            assert_eq!(
                render_eip712_string_preimage(&field(FormatOp::Raw as u8, 1), &mut pages, &invalid,),
                Err(RenderErr::Reject("7730 string not displayable"))
            );
            assert_eq!(pages.len, before_len);
            assert_eq!(pages.buf, before_buf);
        }
    }

    #[test]
    fn eip712_string_page_budget_refusal_is_atomic() {
        let mut pages = Pages::with_len(MAX_PAGES - 3);
        pages.buf[MAX_PAGES - 4][0][0] = b'Z';
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_eip712_string_preimage(
                &field(FormatOp::Raw as u8, 1),
                &mut pages,
                &[b'x'; EIP712_STRING_PREIMAGE_MAX],
            ),
            Err(RenderErr::PageBudget)
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }

    #[test]
    fn eip712_string_hash_word_requires_exact_direct_static_path() {
        const DIRECT_SLOT_ONE: [u8; 6] = [
            0,
            4,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            1,
        ];
        const WITH_FOLLOW_OFFSET: [u8; 7] = [
            0,
            5,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            1,
            PathOp::FollowOffset as u8,
        ];
        let mut body = [0u8; 64];
        body[32..].fill(0x5a);
        let direct = resolve_eip712_string_hash_word(
            &ir(&DIRECT_SLOT_ONE),
            &field(FormatOp::Raw as u8, 1),
            &body,
            2,
        )
        .unwrap();
        assert_eq!(direct, &[0x5a; 32]);

        assert_eq!(
            resolve_eip712_string_hash_word(
                &ir(&DIRECT_SLOT_ONE),
                &field(FormatOp::Raw as u8, 1),
                &body,
                1,
            ),
            Err(RenderErr::Reject("7730 string hash slot"))
        );
        assert_eq!(
            resolve_eip712_string_hash_word(
                &ir(&WITH_FOLLOW_OFFSET),
                &field(FormatOp::Raw as u8, 1),
                &body,
                2,
            ),
            Err(RenderErr::Reject("7730 string hash path shape"))
        );
    }

    #[test]
    fn dynamic_root_offset_must_be_inside_declared_head() {
        let malicious = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            3,
            PathOp::FollowOffset as u8,
        ];
        assert_eq!(
            validate_root_program_static_head(&malicious, 2),
            Err(RenderErr::Reject("7730 root outside static head"))
        );
    }

    #[test]
    fn dirty_address_padding_is_rejected() {
        let mut word = [0u8; 32];
        word[0] = 1;
        word[12..].copy_from_slice(&[0xAA; 20]);
        assert_eq!(
            canonical_address_word(&word),
            Err(RenderErr::Reject("7730 noncanonical address"))
        );
    }

    #[test]
    fn every_address_formatter_rejects_dirty_high_padding() {
        let mut body = [0u8; 32];
        body[0] = 1;
        body[12..].copy_from_slice(&[0xAA; 20]);
        let ir = ir(&SLOT_POOL);
        let tx = tx();
        let resolver = NameResolver::new();

        let mut ticker_pages = Pages::with_len(0);
        assert_eq!(
            render_token_ticker(
                &field(FormatOp::TokenTicker as u8, 1),
                &mut ticker_pages,
                &ir,
                &body,
                &tx,
                None,
                &resolver,
                &ParamSet::default(),
            ),
            Err(RenderErr::Reject("7730 noncanonical address"))
        );

        let mut interop_pages = Pages::with_len(0);
        assert_eq!(
            render_interop_address_name(
                &field(FormatOp::InteroperableAddressName as u8, 1),
                &mut interop_pages,
                &ir,
                &body,
                &tx,
                &resolver,
            ),
            Err(RenderErr::Reject("7730 noncanonical address"))
        );
    }

    #[test]
    fn interoperable_address_renders_u64_chain_id_losslessly() {
        let mut body = [0u8; 32];
        body[12..].copy_from_slice(&[0x11; 20]);
        let mut tx = tx();
        tx.chain_id = u64::MAX;
        let mut pages = Pages::with_len(0);
        render_interop_address_name(
            &field(FormatOp::InteroperableAddressName as u8, 1),
            &mut pages,
            &ir(&SLOT_POOL),
            &body,
            &tx,
            &NameResolver::new(),
        )
        .unwrap();
        assert_eq!(&pages.buf[0][1][..7], b"eip155:");
        assert_eq!(&pages.buf[0][2], b"184467440737095>");
        assert_eq!(&pages.buf[0][3][..6], b"51615:");
    }

    #[test]
    fn const_cannot_override_a_real_path_or_unknown_format() {
        let mut params = ParamSet::default();
        params.const_value = Some(b"benign");
        let resolver = NameResolver::new();
        let mut pages = Pages::with_len(0);
        assert_eq!(
            dispatch(
                &field(FormatOp::Raw as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &[0u8; 32],
                &tx(),
                None,
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 bad const shape"))
        );
        assert_eq!(
            dispatch(
                &field(0xFF, 0),
                &mut pages,
                &ir(&SLOT_POOL),
                &[],
                &tx(),
                None,
                &resolver,
                &params,
            ),
            Err(RenderErr::Reject("7730 bad format op"))
        );
    }

    fn router02_path_ir() -> Erc7730Ir<'static> {
        static POOL: [u8; 11] = [
            0,
            9,
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FollowOffset as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FollowOffset as u8,
        ];
        ir(&POOL)
    }

    fn router02_body(path: &[u8]) -> std::vec::Vec<u8> {
        fn push_word(body: &mut std::vec::Vec<u8>, value: usize) {
            let mut word = [0u8; 32];
            word[24..].copy_from_slice(&(value as u64).to_be_bytes());
            body.extend_from_slice(&word);
        }

        let mut body = std::vec::Vec::new();
        push_word(&mut body, 32); // outer tuple offset
        push_word(&mut body, 128); // tuple path offset
        push_word(&mut body, 1); // canonical recipient address(1)
        push_word(&mut body, 7); // amount A
        push_word(&mut body, 11); // amount B
        push_word(&mut body, path.len());
        body.extend_from_slice(path);
        body.resize(body.len() + (32 - path.len() % 32) % 32, 0);
        body
    }

    fn assert_route_address(page: &[[u8; DISPLAY_COLS]; 4], address: &[u8; 20]) {
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        let mut r3 = [b' '; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, address);
        assert_eq!(page[1], r1);
        assert_eq!(page[2], r2);
        assert_eq!(page[3], r3);
    }

    #[test]
    fn uniswap_v3_route_renders_every_token_and_fee_in_selector_direction() {
        let token_a = [0x11; 20];
        let token_b = [0x22; 20];
        let token_c = [0x33; 20];
        let mut packed = std::vec::Vec::new();
        packed.extend_from_slice(&token_a);
        packed.extend_from_slice(&[0x00, 0x0b, 0xb8]); // 3000 ppm
        packed.extend_from_slice(&token_b);
        packed.extend_from_slice(&[0x00, 0x01, 0xf4]); // 500 ppm
        packed.extend_from_slice(&token_c);
        let body = router02_body(&packed);
        let route = field(FormatOp::UniswapV3Path as u8, 1);
        let mut params = ParamSet::default();
        params.terminal_kind = Some(TerminalKind::DynamicBytes);
        params.dynamic_kind = Some(DYNAMIC_KIND_BYTES);

        let mut forward = Pages::with_len(0);
        render_uniswap_v3_path(
            &route,
            &mut forward,
            &router02_path_ir(),
            &body,
            Direction::Forward,
            &params,
        )
        .expect("forward route renders");
        assert_eq!(forward.len, 5);
        assert_eq!(&forward.buf[0][0][..5], b"Route");
        assert_route_address(&forward.buf[0], &token_a);
        assert_eq!(&forward.buf[1][0][..14], b"Pool fee (ppm)");
        assert_eq!(&forward.buf[1][1][..8], b"3000 ppm");
        assert_eq!(forward.buf[1][2], [b' '; DISPLAY_COLS]);
        assert_eq!(forward.buf[1][3], [b' '; DISPLAY_COLS]);
        assert_route_address(&forward.buf[2], &token_b);
        assert_eq!(&forward.buf[3][1][..7], b"500 ppm");
        assert_route_address(&forward.buf[4], &token_c);

        let mut reverse = Pages::with_len(0);
        render_uniswap_v3_path(
            &route,
            &mut reverse,
            &router02_path_ir(),
            &body,
            Direction::Reverse,
            &params,
        )
        .expect("reverse route renders");
        assert_eq!(reverse.len, 5);
        assert_route_address(&reverse.buf[0], &token_c);
        assert_eq!(&reverse.buf[1][1][..7], b"500 ppm");
        assert_route_address(&reverse.buf[2], &token_b);
        assert_eq!(&reverse.buf[3][1][..8], b"3000 ppm");
        assert_route_address(&reverse.buf[4], &token_a);
    }

    #[test]
    fn uniswap_v3_route_page_exhaustion_refuses_without_truncation_success() {
        let mut packed = std::vec::Vec::new();
        packed.extend_from_slice(&[0x11; 20]);
        packed.extend_from_slice(&[0x00, 0x0b, 0xb8]);
        packed.extend_from_slice(&[0x22; 20]);
        let body = router02_body(&packed);
        let route = field(FormatOp::UniswapV3Path as u8, 1);
        let mut params = ParamSet::default();
        params.terminal_kind = Some(TerminalKind::DynamicBytes);
        params.dynamic_kind = Some(DYNAMIC_KIND_BYTES);
        let mut pages = Pages::with_len(crate::display::MAX_PAGES - 2);
        assert_eq!(
            render_uniswap_v3_path(
                &route,
                &mut pages,
                &router02_path_ir(),
                &body,
                Direction::Forward,
                &params,
            ),
            Err(RenderErr::PageBudget)
        );
    }

    #[test]
    fn authenticated_amount_over_capacity_refuses_atomically() {
        // 10^72 is mathematically exact at 18 decimals but its canonical
        // scaled text cannot fit the two trusted value rows. An authenticated
        // scale may not silently downgrade to raw after page publication.
        let word = exact_eighteen_decimal_overflow_word();
        let mut pages = sentinel_pages();
        let before_len = pages.len;
        let before_buf = pages.buf;
        assert_eq!(
            render_amount(
                &field(FormatOp::Amount as u8, 1),
                &mut pages,
                &ir(&SLOT_POOL),
                &word,
                &tx(),
                &ParamSet::default(),
            ),
            Err(RenderErr::Reject("7730 inexact scaled value"))
        );
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
    }
}
