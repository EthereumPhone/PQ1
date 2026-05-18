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
    let end = off.checked_add(32)?;
    body.get(off..end)
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

    // ---------------------------------------------------------------
    // Hardened length-word reader helpers shared by the new tests.
    // The walker decodes offsets/lengths from 32-byte big-endian words
    // and explicitly requires the top 28 bytes to be zero (anything
    // else is malformed). Build words that exercise those edges.
    // ---------------------------------------------------------------

    fn word_with_top_byte_set() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[0] = 0x01;
        w
    }

    fn word_just_below_top_28_zero_boundary() -> [u8; 32] {
        // First byte that the offset/length reader scans (index 27)
        // — this is the highest byte still inside the "must be zero"
        // range. Any non-zero byte in 0..28 must trip the reader.
        let mut w = [0u8; 32];
        w[27] = 0x01;
        w
    }

    // ---------------------------------------------------------------
    // MAX_DYNAMIC_LEN regression — pin the cap from a black-box angle.
    // The walker accepts a dynamic length of exactly MAX_DYNAMIC_LEN
    // (provided the body is sized for it) and rejects MAX_DYNAMIC_LEN+1.
    // We don't allocate a real 1 MiB body — instead we trigger the cap
    // check by claiming a length one over the boundary.
    // ---------------------------------------------------------------

    #[test]
    fn positive_constants_are_frozen() {
        assert_eq!(MAX_DYNAMIC_LEN, 1 << 20, "MAX_DYNAMIC_LEN frozen");
    }

    #[test]
    fn negative_dynamic_length_exceeds_cap_rejected() {
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32)); // offset = 32 (canonical)
        // Claim length = MAX_DYNAMIC_LEN + 1. Anything that big is
        // attacker-crafted; the cap exists to bound rendering work.
        body.extend_from_slice(&word_be32(MAX_DYNAMIC_LEN + 1));
        // Pad with zeros so length-fits-in-body isn't the early-exit
        // reason — we want MAX_DYNAMIC_LEN itself to be what trips.
        body.extend(std::iter::repeat(0u8).take(((MAX_DYNAMIC_LEN + 1) as usize + 31) & !31));
        assert!(walk(&parsed, &body).is_none());
    }

    // ---------------------------------------------------------------
    // Positive — every static-primitive type is admitted.
    // ---------------------------------------------------------------

    #[test]
    fn positive_all_static_primitives_walk() {
        for tysig in [
            b"f(address)".as_slice(),
            b"f(bool)",
            b"f(uint8)",
            b"f(uint256)",
            b"f(int8)",
            b"f(int256)",
            b"f(bytes1)",
            b"f(bytes32)",
        ] {
            let parsed = parse_text_sig(tysig).expect("sig parses");
            let body = vec![0u8; 32];
            let w = walk(&parsed, &body)
                .unwrap_or_else(|| panic!("walk must accept {:?}", tysig));
            assert_eq!(w.arg_count, 1);
            assert_eq!(w.args[0].body_off, 0);
            assert_eq!(w.args[0].count, 1);
        }
    }

    #[test]
    fn positive_max_static_array_accepted() {
        // T[256] is exactly the cap.
        let parsed = parse_text_sig(b"f(uint256[256])").unwrap();
        let body = vec![0u8; 32 * 256];
        let w = walk(&parsed, &body).expect("256-element static array OK");
        assert_eq!(w.args[0].count, 256);
    }

    #[test]
    fn positive_multiple_dyn_args_canonical_packing() {
        // foo(bytes,bytes) — two dyn args. Canonical packing puts both
        // tails back-to-back after a 2-word head.
        let parsed = parse_text_sig(b"foo(bytes,bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(64));  // offset of arg0 tail
        body.extend_from_slice(&word_be32(128)); // offset of arg1 tail
        body.extend_from_slice(&word_be32(3));   // arg0 length
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&[0u8; 29]); // pad to 32
        body.extend_from_slice(&word_be32(4));   // arg1 length
        body.extend_from_slice(b"defg");
        body.extend_from_slice(&[0u8; 28]); // pad to 32
        let w = walk(&parsed, &body).expect("canonical 2x dyn must walk");
        assert_eq!(w.arg_count, 2);
        assert_eq!(w.args[0].count, 3);
        assert_eq!(w.args[1].count, 4);
        // body_off points at the *length* word, not the payload.
        assert_eq!(w.args[0].body_off, 64);
        assert_eq!(w.args[1].body_off, 128);
    }

    #[test]
    fn positive_string_walks_like_bytes() {
        let parsed = parse_text_sig(b"f(string)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(5));
        body.extend_from_slice(b"hello");
        body.extend_from_slice(&[0u8; 27]);
        let w = walk(&parsed, &body).expect("string walks");
        assert_eq!(w.args[0].count, 5);
    }

    #[test]
    fn positive_dyn_bytes_zero_length() {
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(0));
        // Zero-length: payload_padded == 0 → end == offset+32 == 64.
        let w = walk(&parsed, &body).expect("zero-length bytes OK");
        assert_eq!(w.args[0].count, 0);
    }

    #[test]
    fn positive_dyn_array_of_addresses() {
        let parsed = parse_text_sig(b"f(address[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));   // offset
        body.extend_from_slice(&word_be32(2));    // length=2
        body.extend_from_slice(&addr_word(0xaa));
        body.extend_from_slice(&addr_word(0xbb));
        let w = walk(&parsed, &body).expect("address[] walks");
        assert_eq!(w.args[0].count, 2);
    }

    #[test]
    fn positive_dyn_array_of_bool() {
        let parsed = parse_text_sig(b"f(bool[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(2));
        let mut t = [0u8; 32];
        t[31] = 1;
        body.extend_from_slice(&t);                 // true
        body.extend_from_slice(&[0u8; 32]);         // false
        let w = walk(&parsed, &body).expect("bool[] walks");
        assert_eq!(w.args[0].count, 2);
        assert_eq!(read_bool(&body, w.args[0].body_off + 32).unwrap(), true);
        assert_eq!(read_bool(&body, w.args[0].body_off + 64).unwrap(), false);
    }

    #[test]
    fn positive_mixed_static_then_dynamic() {
        // f(address,bytes) — head 64 (one addr word + one offset word).
        let parsed = parse_text_sig(b"f(address,bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&addr_word(0xcc));    // address
        body.extend_from_slice(&word_be32(64));      // offset of tail
        body.extend_from_slice(&word_be32(4));       // length=4
        body.extend_from_slice(b"DATA");
        body.extend_from_slice(&[0u8; 28]);
        let w = walk(&parsed, &body).expect("static+dyn must walk");
        assert_eq!(read_address(&body, w.args[0].body_off).unwrap(), [0xcc; 20]);
        assert_eq!(w.args[1].body_off, 64);
        assert_eq!(w.args[1].count, 4);
    }

    #[test]
    fn positive_empty_body_zero_arg_sig() {
        let parsed = parse_text_sig(b"f()").unwrap();
        let w = walk(&parsed, &[]).expect("0-arg with empty body OK");
        assert_eq!(w.arg_count, 0);
    }

    #[test]
    fn positive_static_array_of_bytes32() {
        let parsed = parse_text_sig(b"f(bytes32[2])").unwrap();
        let body = vec![0u8; 64];
        let w = walk(&parsed, &body).expect("bytes32[2] static array OK");
        assert_eq!(w.args[0].count, 2);
    }

    // ---------------------------------------------------------------
    // Negative — offset/length top-bytes-zero gate.
    //
    // Solidity ABI offsets and lengths are 32-byte big-endian words.
    // The on-chain encoder always pads the top 28 bytes to zero. We
    // refuse anything else — a single non-zero byte above the 32-bit
    // window is attacker-controlled noise that could (a) collide
    // accidentally on length comparisons or (b) signal a wallet that
    // doesn't enforce the gate to interpret the value differently
    // from the contract.
    // ---------------------------------------------------------------

    #[test]
    fn negative_offset_word_top_28_nonzero_rejected() {
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_with_top_byte_set()); // top byte != 0
        body.extend_from_slice(&word_be32(0));
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_offset_word_byte_27_nonzero_rejected() {
        // Byte index 27 is the last byte inside the "must be zero" prefix.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_just_below_top_28_zero_boundary());
        body.extend_from_slice(&word_be32(0));
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_length_word_top_28_nonzero_rejected() {
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));               // canonical offset
        body.extend_from_slice(&word_with_top_byte_set());    // bad length word
        body.extend_from_slice(&[0u8; 32]);
        assert!(walk(&parsed, &body).is_none());
    }

    // ---------------------------------------------------------------
    // Negative — non-canonical packing rules.
    //
    // The walker REQUIRES dyn tails appear in arg order, immediately
    // after the static head, each padded to 32-byte alignment. Any
    // other layout is rejected — this is exactly the "spoofing avenue"
    // mentioned in the module docstring.
    // ---------------------------------------------------------------

    #[test]
    fn negative_offset_points_inside_head_rejected() {
        // f(bytes,bytes) but arg1's offset is 0 (inside head), trying
        // to alias arg1's "length" word with arg0's offset word.
        let parsed = parse_text_sig(b"f(bytes,bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(64)); // arg0 offset = 64 (canonical)
        body.extend_from_slice(&word_be32(0));  // arg1 offset = 0 (HEAD overlap)
        body.extend_from_slice(&word_be32(0));  // arg0 length
        body.extend_from_slice(&[0u8; 32]);
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_dyn_args_reordered_tails_rejected() {
        // Two dyn args where arg1's tail appears BEFORE arg0's tail.
        let parsed = parse_text_sig(b"f(bytes,bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(128)); // arg0 offset (later tail)
        body.extend_from_slice(&word_be32(64));  // arg1 offset (earlier tail)
        body.extend_from_slice(&word_be32(4));   // arg1 tail first
        body.extend_from_slice(b"AAAA");
        body.extend_from_slice(&[0u8; 28]);
        body.extend_from_slice(&word_be32(4));   // arg0 tail second
        body.extend_from_slice(b"BBBB");
        body.extend_from_slice(&[0u8; 28]);
        // tail_cursor after arg0 expects 128 (== head_size), but arg0
        // claims 128 from a head that's only 64 bytes long → reject.
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_gap_between_tails_rejected() {
        // f(bytes,bytes): arg0 tail ends at 96, arg1 claims offset
        // 128 — leaves a 32-byte gap. Non-canonical.
        let parsed = parse_text_sig(b"f(bytes,bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(64));  // arg0 offset (canonical)
        body.extend_from_slice(&word_be32(128)); // arg1 offset (gap of 32)
        body.extend_from_slice(&word_be32(0));   // arg0 length=0 → tail_cursor=96
        body.extend_from_slice(&[0u8; 32]);      // 32-byte gap
        body.extend_from_slice(&word_be32(0));   // arg1 length=0
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_offset_zero_rejected_with_dyn_only() {
        // f(bytes) where the offset is 0 — overlaps the head.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(0)); // offset == 0 → not canonical
        body.extend_from_slice(&word_be32(0));
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_offset_unaligned_rejected() {
        // Offset that isn't a multiple of 32 — tail_cursor starts at
        // head_size (32) so even a "valid-looking" non-32-aligned
        // offset of, say, 33 can never match.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(33));
        body.extend_from_slice(&[0u8; 32]);
        assert!(walk(&parsed, &body).is_none());
    }

    // ---------------------------------------------------------------
    // Negative — length / padding boundary attacks.
    // ---------------------------------------------------------------

    #[test]
    fn negative_dyn_bytes_length_overflow_u32_in_u64_padding() {
        // length close to u32::MAX would (a) be over MAX_DYNAMIC_LEN
        // (which is 2^20). The walker's first cap check trips. This
        // pins the "we never overflow u64 in payload_padded" guarantee
        // even if MAX_DYNAMIC_LEN were ever loosened: the body cannot
        // actually be 4 GiB on a 32-bit MCU, so the `end > body.len()`
        // check would catch it too.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(0xFFFF_FFFF));
        body.extend_from_slice(&[0u8; 64]);
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_dyn_bytes_length_one_byte_short_rejected() {
        // length=32 needs 32 bytes of payload. Provide only 31 → not
        // 32-byte aligned and not enough body. Body length isn't a
        // multiple of 32 anyway, so the alignment gate kills it first.
        let parsed = parse_text_sig(b"f(bytes)").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&[0u8; 31]);
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_dyn_array_length_overflow_rejected() {
        // dyn array of uint256: payload is length*32. With
        // length = MAX_DYNAMIC_LEN we'd need MAX_DYNAMIC_LEN*32 bytes
        // (32 MiB) — way more than any realistic body. With length =
        // MAX_DYNAMIC_LEN + 1 we trip the cap check directly.
        let parsed = parse_text_sig(b"f(uint256[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(MAX_DYNAMIC_LEN + 1));
        body.extend_from_slice(&[0u8; 64]);
        assert!(walk(&parsed, &body).is_none());
    }

    // ---------------------------------------------------------------
    // Negative — types that the Phase 2 first-cut decides to decline
    // even though the parser accepts them. The contract here is
    // STRICTLY: any type the renderer can't safely show → blind sign.
    // ---------------------------------------------------------------

    #[test]
    fn negative_dynamic_array_of_dynamic_bytes_declined() {
        // bytes[] — element is itself dynamic. is_static_primitive
        // returns false → classify yields Decline.
        let parsed = parse_text_sig(b"f(bytes[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(0));
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_dynamic_array_of_string_declined() {
        let parsed = parse_text_sig(b"f(string[])").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32));
        body.extend_from_slice(&word_be32(0));
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_static_array_of_array_declined() {
        // uint256[2][3] — outer fixed-size element is itself an array,
        // so the static-primitive check on the element rejects.
        let parsed = parse_text_sig(b"f(uint256[2][3])").unwrap();
        let body = vec![0u8; 32 * 6];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_array_of_tuple_declined() {
        // (uint256)[2] — element is a tuple. is_static_primitive →
        // false → Decline.
        let parsed = parse_text_sig(b"f((uint256)[2])").unwrap();
        let body = vec![0u8; 64];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_tuple_top_level_declined_with_canonical_body() {
        // Even with a perfectly canonical body, the walker MUST reject
        // tuples — the renderer can't safely display them in Phase 2.
        // This pins the "tuples → blind sign" contract.
        let parsed = parse_text_sig(b"f((address,uint256))").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&addr_word(0xaa));
        body.extend_from_slice(&word_be32(1));
        assert!(
            walk(&parsed, &body).is_none(),
            "tuple must be declined regardless of body shape",
        );
    }

    // ---------------------------------------------------------------
    // Negative — body geometry that mismatches the static head.
    // ---------------------------------------------------------------

    #[test]
    fn negative_body_just_one_word_short_rejected() {
        // f(uint256,uint256,uint256) — head = 96 bytes. Provide 64.
        let parsed = parse_text_sig(b"f(uint256,uint256,uint256)").unwrap();
        let body = vec![0u8; 64];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_body_one_word_too_long_rejected() {
        // f(uint256) head = 32. Provide 64. Trailing word is residual.
        let parsed = parse_text_sig(b"f(uint256)").unwrap();
        let body = vec![0u8; 64];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_body_misaligned_by_one_rejected() {
        // body.len() % 32 != 0. Even with the right total head size,
        // alignment must be enforced first to keep the per-word
        // indexing math safe.
        let parsed = parse_text_sig(b"f(uint256)").unwrap();
        let body = vec![0u8; 33];
        assert!(walk(&parsed, &body).is_none());
    }

    #[test]
    fn negative_body_empty_with_non_empty_sig_rejected() {
        let parsed = parse_text_sig(b"f(uint256)").unwrap();
        assert!(walk(&parsed, &[]).is_none());
    }

    // ---------------------------------------------------------------
    // Word readers — exhaustive boundary tests.
    // ---------------------------------------------------------------

    #[test]
    fn positive_read_address_min_max_offsets() {
        let mut body = vec![0u8; 64];
        // Word at offset 0.
        for i in 12..32 {
            body[i] = 0x11;
        }
        // Word at offset 32.
        for i in (32 + 12)..64 {
            body[i] = 0x22;
        }
        assert_eq!(read_address(&body, 0).unwrap(), [0x11; 20]);
        assert_eq!(read_address(&body, 32).unwrap(), [0x22; 20]);
    }

    #[test]
    fn negative_read_address_offset_past_end() {
        let body = vec![0u8; 32];
        assert!(read_address(&body, 1).is_none()); // unaligned + past
        assert!(read_address(&body, 32).is_none()); // exactly past
    }

    #[test]
    fn negative_read_address_top_byte_in_padding_zone_nonzero() {
        // The walker has no opinion about this — the shape pass passes.
        // The read_address shim defers to decode_address_word which
        // pins the "top 12 bytes are zero" invariant. Probe each of
        // those 12 bytes individually so a future regression in the
        // shim or in the underlying decoder is loudly caught.
        for bad_byte_idx in 0..12 {
            let mut body = vec![0u8; 32];
            body[bad_byte_idx] = 0x01;
            assert!(
                read_address(&body, 0).is_none(),
                "byte {} in address top-pad must be zero",
                bad_byte_idx,
            );
        }
    }

    #[test]
    fn positive_read_u256_full_value() {
        // u256 reader keeps the whole 32-byte word as-is (no top-byte
        // gate — uint256 fills the word).
        let mut body = vec![0u8; 32];
        for (i, b) in body.iter_mut().enumerate() {
            *b = i as u8;
        }
        let v = read_u256(&body, 0).unwrap();
        for i in 0..32 {
            assert_eq!(v.0[i], i as u8);
        }
    }

    #[test]
    fn negative_read_u256_past_end() {
        let body = vec![0u8; 32];
        assert!(read_u256(&body, 1).is_none());
    }

    #[test]
    fn positive_read_bool_true_and_false() {
        let mut body = vec![0u8; 64];
        body[31] = 0; // word 0 = false
        body[63] = 1; // word 1 = true
        assert_eq!(read_bool(&body, 0).unwrap(), false);
        assert_eq!(read_bool(&body, 32).unwrap(), true);
    }

    #[test]
    fn negative_read_bool_other_lsb_rejected() {
        // The on-chain bool packing is canonical: word[31] ∈ {0, 1},
        // word[0..31] all zero. Anything else is malformed — refuse.
        // (A wallet that interpreted 0xff as `true` would disagree
        // with the contract.)
        for bad in [2u8, 0x10, 0x7f, 0x80, 0xff] {
            let mut body = vec![0u8; 32];
            body[31] = bad;
            assert!(
                read_bool(&body, 0).is_none(),
                "bool LSB {} must be rejected",
                bad,
            );
        }
    }

    #[test]
    fn negative_read_bool_nonzero_in_padding_zone() {
        // Even if word[31] is the canonical 1, a non-zero in 0..31
        // must reject.
        let mut body = vec![0u8; 32];
        body[31] = 1;
        body[10] = 1;
        assert!(read_bool(&body, 0).is_none());
    }

    #[test]
    fn negative_read_bool_past_end() {
        let body = vec![0u8; 32];
        assert!(read_bool(&body, 1).is_none());
    }

    #[test]
    fn positive_word_at_valid_offsets() {
        let body = vec![0u8; 64];
        assert!(word(&body, 0).is_some());
        assert!(word(&body, 32).is_some());
    }

    #[test]
    fn negative_word_offset_unaligned_or_past() {
        let body = vec![0u8; 64];
        assert!(word(&body, 33).is_none());
        // off+32 > len — past end.
        assert!(word(&body, 64).is_none());
        assert!(word(&body, 65).is_none());
    }

    /// Production-code bug surfaced: `word()` computes `off + 32`
    /// without overflow protection. An attacker-supplied offset near
    /// `usize::MAX` makes the addition wrap and panic in debug /
    /// `overflow-checks = true` builds (the release profile in
    /// `secure/Cargo.toml` enables overflow checks). The CORRECT
    /// behaviour is to return `None` — same as any other out-of-range
    /// offset — never panic on attacker bytes. The walker's geometry
    /// passes prevent this offset from ever reaching `word()` today,
    /// but the helper is `pub(crate)` and any future renderer that
    /// calls it directly inherits the panic.
    ///
    /// Fix: replace `body.get(off..off + 32)` with
    /// `body.get(off..off.checked_add(32)?)` (or use `usize::saturating_add`).
    #[test]
    fn negative_word_offset_overflow_should_return_none() {
        let body = vec![0u8; 64];
        // `off + 32` would wrap usize at `usize::MAX - 16`; the
        // `checked_add` guard in word() must return None instead of
        // panicking.
        assert!(word(&body, usize::MAX - 16).is_none());
    }

    // ---------------------------------------------------------------
    // Stress / regression — combined head+tail with many args, just
    // to make sure the head_pos/tail_cursor accounting stays exact
    // even with multiple static-and-dynamic arg classes interleaved.
    // ---------------------------------------------------------------

    #[test]
    fn positive_three_static_two_dynamic_interleaved() {
        // f(address,bytes,uint256,bytes,bool)
        let parsed = parse_text_sig(b"f(address,bytes,uint256,bytes,bool)").unwrap();
        // head = 5 * 32 = 160.
        // arg1 (bytes) tail at offset 160, length=0 → next at 192.
        // arg3 (bytes) tail at offset 192, length=0 → next at 224.
        let mut body = Vec::new();
        body.extend_from_slice(&addr_word(0xee));
        body.extend_from_slice(&word_be32(160)); // offset arg1
        body.extend_from_slice(&word_be32(99));  // uint256
        body.extend_from_slice(&word_be32(192)); // offset arg3
        // canonical bool: word[31] = 1.
        let mut true_word = [0u8; 32];
        true_word[31] = 1;
        body.extend_from_slice(&true_word);
        body.extend_from_slice(&word_be32(0)); // arg1 length=0
        body.extend_from_slice(&word_be32(0)); // arg3 length=0
        let w = walk(&parsed, &body).expect("interleaved walk OK");
        assert_eq!(w.arg_count, 5);
        assert_eq!(w.args[0].count, 1); // static prim
        assert_eq!(w.args[1].count, 0); // bytes len=0
        assert_eq!(w.args[2].count, 1); // static prim
        assert_eq!(w.args[3].count, 0); // bytes len=0
        assert_eq!(w.args[4].count, 1); // static prim
    }
}
