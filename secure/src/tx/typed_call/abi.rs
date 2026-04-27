//! Strict Solidity-ABI walker for the Phase 2 typed-args render.
//!
//! Two passes per the handoff doc § Sub-component 2:
//!
//!   1. **Shape pass** — verify the calldata body's geometry matches
//!      the parsed type list. Refuses any out-of-range offset/length,
//!      any non-canonical packing, any overall length mismatch.
//!   2. **Render pass** — runs only after shape pass succeeded; iterates
//!      the captured per-arg records and hands each one to the renderer.
//!
//! Strictness — Phase 2 first cut admits ONLY:
//!
//!   * Static primitives: `uintN`, `intN`, `address`, `bool`, `bytesN`.
//!   * `T[N]` and `T[]` where `T` is a static primitive (above).
//!   * Dynamic `bytes` / `string`.
//!
//! Tuples, nested arrays, and arrays whose element is itself dynamic
//! cause the walker to return `None` ⇒ the renderer falls back to the
//! Phase 1 BLIND SIGN flow. The handoff doc explicitly names tuples /
//! nested arrays as Phase 2 out-of-scope (see `out-of-scope risks`).
//!
//! Canonical packing — the walker REQUIRES dynamic tails to appear in
//! arg order, immediately after the static head, with each tail padded
//! to a 32-byte boundary. Standard Solidity ABI encoders produce this
//! shape. Any deviation (gaps, reordering, overlap) ⇒ fall back. This
//! is stricter than the spec but safer for a trusted display: a
//! non-canonical encoding that the wallet types differently from the
//! contract is exactly the spoofing avenue we want to refuse.

use crate::erc20::calldata::{decode_address_word, decode_u256_word};
use crate::tx::eip1559::U256;

use super::parser::{ParsedSig, TypeId, TypeRef, MAX_ARGS};

/// One walked top-level arg, ready for the renderer to consume.
#[derive(Clone, Copy)]
pub(crate) struct Walked {
    pub(crate) type_id: TypeId,
    /// Byte offset into the body slice (`inner_data[4..]`).
    ///
    ///   * Static primitive          → start of the 32-byte head word
    ///   * Static array `T[N]`        → start of the first inline element
    ///   * Dynamic `bytes`/`string`   → start of the length word in tail
    ///   * Dynamic `T[]`              → start of the length word in tail
    pub(crate) body_off: usize,
    /// Element count.
    ///
    ///   * Static primitive  → 1 (unused)
    ///   * Static array T[N] → N
    ///   * Dynamic bytes/string → length in BYTES
    ///   * Dynamic T[]        → length in ELEMENTS
    pub(crate) count: u32,
}

pub(crate) struct WalkedSig {
    pub(crate) args: [Walked; MAX_ARGS],
    pub(crate) arg_count: usize,
}

/// Hard cap on dynamic length to bound the rendering work and avoid
/// overflow when computing payload sizes. 1 MiB is dramatically more
/// than any sane signing UX and 4× larger than `MAX_TX_LEN`, so any
/// real calldata will pass — we're only filtering attacker-crafted
/// length words like `2^200`.
const MAX_DYNAMIC_LEN: u32 = 1 << 20;

/// Top-level walk. `body` is `inner_data[4..]` — the calldata after
/// the 4-byte selector. Returns `None` on any shape violation OR any
/// type the first cut declines.
pub(crate) fn walk<'a>(parsed: &ParsedSig<'a>, body: &[u8]) -> Option<WalkedSig> {
    if body.len() % 32 != 0 {
        // The ABI head + every dynamic-payload section is 32-byte
        // aligned; any other body length is malformed.
        return None;
    }

    // Pass 1a: classify every top-level arg + sum the static head size.
    // We compute head_size up front so the dynamic-tail-offset checks
    // can refer to it.
    let mut classes: [ArgClass; MAX_ARGS] = [ArgClass::Decline; MAX_ARGS];
    let mut head_size: usize = 0;
    for i in 0..parsed.arg_count {
        let class = classify(parsed, parsed.args[i])?;
        head_size = head_size.checked_add(class.head_size())?;
        classes[i] = class;
    }
    if head_size > body.len() {
        return None;
    }

    // Pass 1b: walk head + tail, validating geometry. Tails MUST appear
    // in arg order, immediately after the static head, each padded to
    // a 32-byte boundary.
    let mut head_pos: usize = 0;
    let mut tail_cursor: usize = head_size;
    let mut walked: [Walked; MAX_ARGS] = [Walked { type_id: 0, body_off: 0, count: 0 }; MAX_ARGS];

    for i in 0..parsed.arg_count {
        let class = classes[i];
        match class {
            ArgClass::StaticPrimitive => {
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: head_pos,
                    count: 1,
                };
                head_pos += 32;
            }
            ArgClass::StaticArray { count } => {
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: head_pos,
                    count,
                };
                head_pos += 32 * count as usize;
            }
            ArgClass::DynBytes | ArgClass::DynString | ArgClass::DynArrayPrim => {
                if head_pos + 32 > body.len() {
                    return None;
                }
                let offset = read_offset_word(&body[head_pos..head_pos + 32])?;
                head_pos += 32;
                if offset != tail_cursor {
                    // Non-canonical packing.
                    return None;
                }
                if offset + 32 > body.len() {
                    return None;
                }
                let length = read_length_word(&body[offset..offset + 32])?;
                if length > MAX_DYNAMIC_LEN {
                    return None;
                }
                let payload_unpadded: u64 = match class {
                    ArgClass::DynBytes | ArgClass::DynString => length as u64,
                    ArgClass::DynArrayPrim => (length as u64) * 32,
                    _ => unreachable!(),
                };
                let payload_padded = round_up_to_32(payload_unpadded)?;
                let end = (offset as u64)
                    .checked_add(32)?
                    .checked_add(payload_padded)?;
                if end > body.len() as u64 {
                    return None;
                }
                tail_cursor = end as usize;
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: offset,
                    count: length,
                };
            }
            ArgClass::Decline => return None,
        }
    }

    if head_pos != head_size {
        return None;
    }
    // Total body length MUST equal head + every tail section. The
    // handoff doc calls this out as the "static-shape match" check.
    if tail_cursor != body.len() {
        return None;
    }

    Some(WalkedSig { args: walked, arg_count: parsed.arg_count })
}

#[derive(Clone, Copy)]
enum ArgClass {
    /// 32-byte head, no tail. Renders directly from the head word.
    StaticPrimitive,
    /// `count * 32` bytes inline in the head, no tail. Element type
    /// is a static primitive.
    StaticArray { count: u32 },
    /// 32-byte offset in head, length+padded-bytes in tail.
    DynBytes,
    DynString,
    /// 32-byte offset in head, length + length*32 in tail. Element
    /// type is a static primitive.
    DynArrayPrim,
    Decline,
}

impl ArgClass {
    fn head_size(self) -> usize {
        match self {
            ArgClass::StaticPrimitive => 32,
            ArgClass::StaticArray { count } => 32 * count as usize,
            ArgClass::DynBytes | ArgClass::DynString | ArgClass::DynArrayPrim => 32,
            ArgClass::Decline => 0,
        }
    }
}

fn classify(parsed: &ParsedSig<'_>, id: TypeId) -> Option<ArgClass> {
    match parsed.arena.get(id) {
        TypeRef::Uint(_)
        | TypeRef::Int(_)
        | TypeRef::Address
        | TypeRef::Bool
        | TypeRef::BytesN(_) => Some(ArgClass::StaticPrimitive),
        TypeRef::Bytes => Some(ArgClass::DynBytes),
        TypeRef::String => Some(ArgClass::DynString),
        TypeRef::Array { elem, fixed_len } => {
            if !is_static_primitive(parsed, *elem) {
                return Some(ArgClass::Decline);
            }
            match fixed_len {
                None => Some(ArgClass::DynArrayPrim),
                Some(n) => {
                    let n = *n;
                    if n == 0 || n > 256 {
                        // Solidity rejects T[0]; cap N to keep the head
                        // size sane (256 * 32 = 8 KiB head is already
                        // larger than any realistic calldata).
                        return Some(ArgClass::Decline);
                    }
                    Some(ArgClass::StaticArray { count: n })
                }
            }
        }
        TypeRef::Tuple { .. } => Some(ArgClass::Decline),
    }
}

fn is_static_primitive(parsed: &ParsedSig<'_>, id: TypeId) -> bool {
    matches!(
        parsed.arena.get(id),
        TypeRef::Uint(_)
            | TypeRef::Int(_)
            | TypeRef::Address
            | TypeRef::Bool
            | TypeRef::BytesN(_)
    )
}

/// Read a 32-byte word as a u32 offset. Top 28 bytes MUST be zero;
/// otherwise the calldata is malformed (or attacker-crafted).
fn read_offset_word(word: &[u8]) -> Option<usize> {
    if word.len() != 32 {
        return None;
    }
    if word[0..28].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Some(u32::from_be_bytes(buf) as usize)
}

/// Read a 32-byte length word, capping at u32::MAX. Same top-zero gate
/// as offsets — anything past 4 GiB is malformed for our purposes.
fn read_length_word(word: &[u8]) -> Option<u32> {
    if word.len() != 32 {
        return None;
    }
    if word[0..28].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Some(u32::from_be_bytes(buf))
}

fn round_up_to_32(n: u64) -> Option<u64> {
    let r = n % 32;
    if r == 0 {
        Some(n)
    } else {
        n.checked_add(32 - r)
    }
}

// ---------------------------------------------------------------------------
// Word readers used by the renderer (pass 2). These are thin wrappers
// over the existing erc20 decoders so the same address-padding /
// big-endian semantics apply.
// ---------------------------------------------------------------------------

pub(crate) fn word(body: &[u8], off: usize) -> Option<&[u8]> {
    body.get(off..off + 32)
}

pub(crate) fn read_address(body: &[u8], off: usize) -> Option<[u8; 20]> {
    decode_address_word(word(body, off)?)
}

pub(crate) fn read_u256(body: &[u8], off: usize) -> Option<U256> {
    Some(decode_u256_word(word(body, off)?))
}

pub(crate) fn read_bool(body: &[u8], off: usize) -> Option<bool> {
    let w = word(body, off)?;
    if w[0..31].iter().any(|&b| b != 0) {
        return None;
    }
    match w[31] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::parser::parse_text_sig;
    use super::*;

    fn build(args: &[(&[u8], &[u8])]) -> Vec<u8> {
        // Trivial concatenator: caller hands us pre-encoded (head, tail)
        // chunks. For the simple negative tests below it's enough.
        let mut head = Vec::new();
        let mut tail = Vec::new();
        for (h, t) in args {
            head.extend_from_slice(h);
            tail.extend_from_slice(t);
        }
        head.extend_from_slice(&tail);
        head
    }

    fn word_be32(v: u32) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[28..32].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn addr_word(addr: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        for i in 12..32 {
            w[i] = addr;
        }
        w
    }

    #[test]
    fn happy_transfer() {
        // transfer(address,uint256) — both static primitives
        let parsed = parse_text_sig(b"transfer(address,uint256)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&addr_word(0xab));
        body.extend_from_slice(&word_be32(1234));
        let walked = walk(&parsed, &body).expect("happy path");
        assert_eq!(walked.arg_count, 2);
        assert_eq!(read_address(&body, walked.args[0].body_off).unwrap(), [0xab; 20]);
        let amount = read_u256(&body, walked.args[1].body_off).unwrap();
        assert_eq!(&amount.0[28..], &1234u32.to_be_bytes());
    }

    #[test]
    fn happy_dyn_bytes() {
        // foo(bytes) — head: 1 offset word; tail: length word + padded data
        let parsed = parse_text_sig(b"foo(bytes)").unwrap();
        let mut body = Vec::new();
        // head: offset = 32 (start of tail)
        body.extend_from_slice(&word_be32(32));
        // tail: length = 5
        body.extend_from_slice(&word_be32(5));
        // payload: "hello" + 27 bytes of zero pad
        body.extend_from_slice(b"hello");
        body.extend_from_slice(&[0u8; 27]);
        let walked = walk(&parsed, &body).expect("happy bytes");
        assert_eq!(walked.args[0].count, 5);
        assert_eq!(walked.args[0].body_off, 32);
    }

    #[test]
    fn rejects_bad_address_pad() {
        let parsed = parse_text_sig(b"f(address)").unwrap();
        let mut body = vec![0u8; 32];
        body[0] = 0xff; // top byte non-zero — left-pad violation
        // shape pass passes (any 32-byte word satisfies geometry); the
        // address read fails downstream. This test pins the
        // erc20 decoder's behaviour through the abi::read_address shim.
        let walked = walk(&parsed, &body).expect("walks");
        assert!(read_address(&body, walked.args[0].body_off).is_none());
    }

    #[test]
    fn rejects_unaligned_body() {
        let parsed = parse_text_sig(b"f(address)").unwrap();
        let body = vec![0u8; 31];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn rejects_short_body() {
        let parsed = parse_text_sig(b"f(uint256,uint256)").unwrap();
        let body = vec![0u8; 32]; // need 64 bytes
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn rejects_residual_bytes() {
        let parsed = parse_text_sig(b"f(uint256)").unwrap();
        let body = vec![0u8; 64]; // 32 extra trailing bytes
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn rejects_non_canonical_offset() {
        // f(bytes) but offset claims to be 64 (past end of head=32).
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(64));   // offset = 64
        body.extend_from_slice(&[0u8; 32]);       // gap
        body.extend_from_slice(&word_be32(0));    // length 0 at offset 64
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn rejects_offset_overflow() {
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(0xff_ff_ff_ff)); // offset way past end
        body.extend_from_slice(&[0u8; 32]);
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn rejects_length_shortfall() {
        // f(bytes) with length=33 but only 32 padded bytes available.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));   // offset = 32
        body.extend_from_slice(&word_be32(33));   // claims 33 bytes
        body.extend_from_slice(&[0u8; 32]);       // only 32 bytes follow
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn declines_tuple() {
        let parsed = parse_text_sig(b"f((uint256,address))").unwrap();
        let body = vec![0u8; 64];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn declines_nested_array() {
        let parsed = parse_text_sig(b"f(uint256[][])").unwrap();
        let body = vec![0u8; 32];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn happy_static_array() {
        // f(uint256[3]) — head: 96 bytes inline, no tail.
        let parsed = parse_text_sig(b"f(uint256[3])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(10));
        body.extend_from_slice(&word_be32(20));
        body.extend_from_slice(&word_be32(30));
        let walked = walk(&parsed, &body).expect("static array happy");
        assert_eq!(walked.args[0].count, 3);
        assert_eq!(walked.args[0].body_off, 0);
    }

    #[test]
    fn happy_dyn_array_uint256() {
        // f(uint256[]) — head: offset; tail: length=2 + 2*32 bytes.
        let parsed = parse_text_sig(b"f(uint256[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));   // offset
        body.extend_from_slice(&word_be32(2));    // length
        body.extend_from_slice(&word_be32(99));   // elem 0
        body.extend_from_slice(&word_be32(100));  // elem 1
        let walked = walk(&parsed, &body).expect("dyn array happy");
        assert_eq!(walked.args[0].count, 2);
    }

    #[test]
    fn rejects_oversize_static_array() {
        // T[257] is past our cap.
        let parsed = parse_text_sig(b"f(uint256[257])").unwrap();
        let body = vec![0u8; 32 * 257];
        assert!(walk(&parsed, &body).is_none());
    }
}
