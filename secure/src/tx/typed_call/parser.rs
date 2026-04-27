//! Text-signature tokenizer for Phase 2 calldata decoding.
//!
//! Consumes the verified `text_sig` slot of a [`SelectorMeta`]
//! (e.g. `transfer(address,uint256)`) and produces a fixed-shape
//! representation usable by the ABI walker in [`super::abi`].
//!
//! Whitelist parity with `tools/build_selectors_json.py` is **load-bearing**:
//! the curator only admits text_sigs the Python validator accepts, so
//! the firmware-side parser MUST accept the same set and reject the
//! same set. Any expansion (e.g. a new fixed-bytesN width, a new uint
//! width) has to land in the Python validator and this file in the
//! same change.
//!
//! Hard caps:
//!   * 16 top-level args
//!   * 32 entries in the type arena (covers nested arrays + tuples)
//!   * 8 levels of array/tuple nesting
//!   * 8 fields per tuple
//!
//! Anything past the caps returns `None` ⇒ blind-sign fallback. No
//! panics on attacker-supplied input — `text_sig` is already
//! Merkle-verified + ASCII-gated upstream, but we still treat it as
//! untrusted bytes.

#![allow(dead_code)]

pub(crate) const MAX_ARGS: usize = 16;
pub(crate) const MAX_TYPE_ARENA: usize = 32;
pub(crate) const MAX_NESTING: u8 = 8;
pub(crate) const MAX_TUPLE_FIELDS: usize = 8;

pub(crate) type TypeId = u16;

/// A single node in the parsed type tree. Arrays and tuples reference
/// other nodes by `TypeId` (index into the surrounding `TypeArena`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum TypeRef {
    /// `uintN` for `N` in 8..=256 (multiple of 8). Bare `uint`
    /// resolves to `Uint(256)` to match Solidity's alias rule.
    Uint(u16),
    /// `intN` for `N` in 8..=256 (multiple of 8). Bare `int`
    /// resolves to `Int(256)`.
    Int(u16),
    Address,
    Bool,
    /// Dynamic-length `bytes`.
    Bytes,
    /// Fixed-length `bytesN`, `N` in 1..=32.
    BytesN(u8),
    /// Dynamic-length `string`.
    String,
    /// `T[N]` (fixed_len = Some(N)) or `T[]` (None). `elem` is the
    /// arena index of the element type.
    Array { elem: TypeId, fixed_len: Option<u32> },
    /// `(T0, T1, ...)`. Up to [`MAX_TUPLE_FIELDS`] components.
    Tuple { fields: [TypeId; MAX_TUPLE_FIELDS], len: u8 },
}

/// Bump-allocator for type nodes. Stack-allocated, no heap.
pub(crate) struct TypeArena {
    types: [TypeRef; MAX_TYPE_ARENA],
    len: usize,
}

impl TypeArena {
    pub(crate) fn new() -> Self {
        Self {
            types: [TypeRef::Bool; MAX_TYPE_ARENA],
            len: 0,
        }
    }

    pub(crate) fn alloc(&mut self, t: TypeRef) -> Option<TypeId> {
        if self.len >= MAX_TYPE_ARENA {
            return None;
        }
        let id = self.len as TypeId;
        self.types[self.len] = t;
        self.len += 1;
        Some(id)
    }

    pub(crate) fn get(&self, id: TypeId) -> &TypeRef {
        &self.types[id as usize]
    }
}

/// Result of `parse_text_sig`: a function name slice borrowed from the
/// input plus the top-level argument list and the type arena that
/// nested types were allocated into.
pub(crate) struct ParsedSig<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) args: [TypeId; MAX_ARGS],
    pub(crate) arg_count: usize,
    pub(crate) arena: TypeArena,
}

/// Top-level entry: parse `name(typelist)`.
///
/// Returns `None` on any shape error (no `(`, no closing `)`, name
/// outside `[A-Za-z_][A-Za-z0-9_]*`, type whitelist violation, or any
/// hard-cap overflow).
pub(crate) fn parse_text_sig(text: &[u8]) -> Option<ParsedSig<'_>> {
    // Find the first '(' and verify the closing ')' is at the very end.
    // Mirrors the Python validator: name(...).
    let open = text.iter().position(|&b| b == b'(')?;
    if open == 0 {
        return None;
    }
    if !text.last().map(|&b| b == b')').unwrap_or(false) {
        return None;
    }
    let name = &text[..open];
    if !is_valid_name(name) {
        return None;
    }
    let body = &text[open + 1..text.len() - 1];

    let mut arena = TypeArena::new();
    let mut args: [TypeId; MAX_ARGS] = [0; MAX_ARGS];
    let mut arg_count = 0usize;

    if !body.is_empty() {
        // Split top-level args on `,`, parse each.
        for part in TopLevelSplit::new(body) {
            let part = part?;
            if arg_count >= MAX_ARGS {
                return None;
            }
            let id = parse_type(&mut arena, part, 0)?;
            args[arg_count] = id;
            arg_count += 1;
        }
    }

    Some(ParsedSig { name, args, arg_count, arena })
}

/// Recursive type parser. Returns the arena id of the parsed node.
fn parse_type(arena: &mut TypeArena, s: &[u8], depth: u8) -> Option<TypeId> {
    if depth > MAX_NESTING {
        return None;
    }
    if s.is_empty() {
        return None;
    }

    // Strip a single trailing `[...]` suffix if present (the rightmost
    // bracket pair). Recurse on the inner type, then wrap in Array.
    if *s.last().unwrap() == b']' {
        let open_idx = find_matching_open_bracket(s)?;
        let suffix = &s[open_idx + 1..s.len() - 1]; // bytes between [ and ]
        let inner = &s[..open_idx];
        if inner.is_empty() {
            return None;
        }
        let fixed_len = if suffix.is_empty() {
            None
        } else {
            Some(parse_u32_decimal(suffix)?)
        };
        let elem = parse_type(arena, inner, depth + 1)?;
        return arena.alloc(TypeRef::Array { elem, fixed_len });
    }

    // Tuple: starts with '(' and ends with ')'.
    if s.first() == Some(&b'(') && s.last() == Some(&b')') {
        let inner = &s[1..s.len() - 1];
        if inner.is_empty() {
            // Empty tuple is not allowed (matches the Python validator).
            return None;
        }
        let mut fields: [TypeId; MAX_TUPLE_FIELDS] = [0; MAX_TUPLE_FIELDS];
        let mut count = 0usize;
        for part in TopLevelSplit::new(inner) {
            let part = part?;
            if count >= MAX_TUPLE_FIELDS {
                return None;
            }
            let id = parse_type(arena, part, depth + 1)?;
            fields[count] = id;
            count += 1;
        }
        if count == 0 {
            return None;
        }
        return arena.alloc(TypeRef::Tuple { fields, len: count as u8 });
    }

    // Primitive.
    let prim = parse_primitive(s)?;
    arena.alloc(prim)
}

/// Find the index of the `[` that pairs with the trailing `]`. Returns
/// `None` if the brackets don't balance.
fn find_matching_open_bracket(s: &[u8]) -> Option<usize> {
    debug_assert_eq!(*s.last().unwrap(), b']');
    let mut depth = 0i32;
    for i in (0..s.len()).rev() {
        match s[i] {
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

/// Parse ASCII decimal digits as a u32. Returns `None` on overflow,
/// leading zero (other than the literal "0"), or any non-digit byte.
fn parse_u32_decimal(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    // Leading zero only allowed for the literal "0" (which is itself
    // disallowed for fixed-array sizes — Solidity rejects `T[0]`).
    if s.len() > 1 && s[0] == b'0' {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?;
        acc = acc.checked_add((b - b'0') as u32)?;
    }
    if acc == 0 {
        return None;
    }
    Some(acc)
}

/// Validate a function name: `^[A-Za-z_][A-Za-z0-9_]*$`. Mirrors the
/// Python validator's `NAME_RE`.
fn is_valid_name(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    for &b in &s[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return false;
        }
    }
    true
}

/// Parse a primitive type token (no array suffix, no tuple parens).
/// Returns `None` for anything outside the curator's whitelist.
fn parse_primitive(s: &[u8]) -> Option<TypeRef> {
    match s {
        b"address" => Some(TypeRef::Address),
        b"bool" => Some(TypeRef::Bool),
        b"string" => Some(TypeRef::String),
        b"bytes" => Some(TypeRef::Bytes),
        b"uint" => Some(TypeRef::Uint(256)),
        b"int" => Some(TypeRef::Int(256)),
        _ => {
            if let Some(width_str) = strip_prefix(s, b"uint") {
                let bits = parse_uint_width(width_str)?;
                Some(TypeRef::Uint(bits))
            } else if let Some(width_str) = strip_prefix(s, b"int") {
                let bits = parse_uint_width(width_str)?;
                Some(TypeRef::Int(bits))
            } else if let Some(width_str) = strip_prefix(s, b"bytes") {
                let n = parse_bytesn_width(width_str)?;
                Some(TypeRef::BytesN(n))
            } else {
                None
            }
        }
    }
}

fn strip_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() <= prefix.len() {
        return None;
    }
    if &s[..prefix.len()] != prefix {
        return None;
    }
    Some(&s[prefix.len()..])
}

/// Validate a `uintN` / `intN` width: must be a multiple of 8 in 8..=256.
fn parse_uint_width(s: &[u8]) -> Option<u16> {
    if s.is_empty() {
        return None;
    }
    if s.len() > 1 && s[0] == b'0' {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?;
        acc = acc.checked_add((b - b'0') as u32)?;
    }
    if acc == 0 || acc > 256 || acc % 8 != 0 {
        return None;
    }
    Some(acc as u16)
}

/// Validate a `bytesN` width: must be in 1..=32.
fn parse_bytesn_width(s: &[u8]) -> Option<u8> {
    if s.is_empty() {
        return None;
    }
    if s.len() > 1 && s[0] == b'0' {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?;
        acc = acc.checked_add((b - b'0') as u32)?;
    }
    if acc == 0 || acc > 32 {
        return None;
    }
    Some(acc as u8)
}

/// Iterator yielding top-level comma-separated chunks of a type list
/// body. Respects nested `(` / `[` so commas inside tuples or array
/// bounds don't split. Each item is `Option<&[u8]>`: `None` signals a
/// shape error (unbalanced parens / brackets, empty chunk).
struct TopLevelSplit<'a> {
    body: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> TopLevelSplit<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, pos: 0, done: false }
    }
}

impl<'a> Iterator for TopLevelSplit<'a> {
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let start = self.pos;
        let mut depth: i32 = 0;
        let mut i = self.pos;
        while i < self.body.len() {
            match self.body[i] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => {
                    depth -= 1;
                    if depth < 0 {
                        // Unbalanced — surface error.
                        self.done = true;
                        return Some(None);
                    }
                }
                b',' if depth == 0 => {
                    let chunk = &self.body[start..i];
                    self.pos = i + 1;
                    if chunk.is_empty() {
                        self.done = true;
                        return Some(None);
                    }
                    return Some(Some(chunk));
                }
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            self.done = true;
            return Some(None);
        }
        self.done = true;
        let chunk = &self.body[start..];
        if chunk.is_empty() {
            return Some(None);
        }
        Some(Some(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_simple() {
        let p = parse_text_sig(b"transfer(address,uint256)").unwrap();
        assert_eq!(p.name, b"transfer");
        assert_eq!(p.arg_count, 2);
        assert!(matches!(p.arena.get(p.args[0]), TypeRef::Address));
        assert!(matches!(p.arena.get(p.args[1]), TypeRef::Uint(256)));
    }

    #[test]
    fn zero_args() {
        let p = parse_text_sig(b"foo()").unwrap();
        assert_eq!(p.name, b"foo");
        assert_eq!(p.arg_count, 0);
    }

    #[test]
    fn bare_uint_int_resolve_to_256() {
        let p = parse_text_sig(b"f(uint,int)").unwrap();
        assert!(matches!(p.arena.get(p.args[0]), TypeRef::Uint(256)));
        assert!(matches!(p.arena.get(p.args[1]), TypeRef::Int(256)));
    }

    #[test]
    fn dynamic_array() {
        let p = parse_text_sig(b"g(uint256[])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: None } => {
                assert!(matches!(p.arena.get(*elem), TypeRef::Uint(256)));
            }
            other => panic!("expected dynamic array, got {:?}", other),
        }
    }

    #[test]
    fn fixed_array() {
        let p = parse_text_sig(b"h(uint256[8])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: Some(8) } => {
                assert!(matches!(p.arena.get(*elem), TypeRef::Uint(256)));
            }
            other => panic!("expected fixed array of 8, got {:?}", other),
        }
    }

    #[test]
    fn nested_array() {
        // uint256[10][] = dynamic array of (fixed array of 10 uint256).
        // The Python validator strips suffixes from the right, so the
        // outermost wrapper is `[]` (the LAST suffix). That makes the
        // outer Array dynamic and its element a fixed-10 Array.
        let p = parse_text_sig(b"f(uint256[10][])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: None } => match p.arena.get(*elem) {
                TypeRef::Array { elem: inner, fixed_len: Some(10) } => {
                    assert!(matches!(p.arena.get(*inner), TypeRef::Uint(256)));
                }
                other => panic!("expected fixed[10], got {:?}", other),
            },
            other => panic!("expected dynamic[], got {:?}", other),
        }
    }

    #[test]
    fn tuple() {
        let p = parse_text_sig(b"f((address,uint256))").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Tuple { fields, len: 2 } => {
                assert!(matches!(p.arena.get(fields[0]), TypeRef::Address));
                assert!(matches!(p.arena.get(fields[1]), TypeRef::Uint(256)));
            }
            other => panic!("expected tuple, got {:?}", other),
        }
    }

    #[test]
    fn bytesn_widths() {
        for n in 1..=32u8 {
            let s = format!("f(bytes{})", n);
            let p = parse_text_sig(s.as_bytes())
                .unwrap_or_else(|| panic!("bytes{} should parse", n));
            assert!(matches!(p.arena.get(p.args[0]), TypeRef::BytesN(m) if *m == n));
        }
    }

    #[test]
    fn rejects_oversized_bytesn() {
        assert!(parse_text_sig(b"f(bytes33)").is_none());
        assert!(parse_text_sig(b"f(bytes0)").is_none());
    }

    #[test]
    fn rejects_bad_uint_width() {
        assert!(parse_text_sig(b"f(uint7)").is_none());
        assert!(parse_text_sig(b"f(uint264)").is_none());
        assert!(parse_text_sig(b"f(uint009)").is_none());
    }

    #[test]
    fn rejects_empty_tuple() {
        assert!(parse_text_sig(b"f(())").is_none());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse_text_sig(b"f(uint256").is_none());
        assert!(parse_text_sig(b"f(uint256))").is_none());
    }

    #[test]
    fn rejects_no_open_paren() {
        assert!(parse_text_sig(b"foo").is_none());
    }

    #[test]
    fn rejects_bad_name() {
        assert!(parse_text_sig(b"9foo(uint256)").is_none());
        assert!(parse_text_sig(b"foo bar(uint256)").is_none());
        assert!(parse_text_sig(b"(uint256)").is_none());
    }

    #[test]
    fn rejects_unknown_primitive() {
        assert!(parse_text_sig(b"f(function)").is_none());
        assert!(parse_text_sig(b"f(fixed128x18)").is_none());
    }

    #[test]
    fn arg_cap() {
        // 17 args > MAX_ARGS=16.
        let mut s = String::from("f(");
        for i in 0..17 {
            if i > 0 {
                s.push(',');
            }
            s.push_str("uint256");
        }
        s.push(')');
        assert!(parse_text_sig(s.as_bytes()).is_none());
    }

    #[test]
    fn nesting_cap() {
        // 9-deep nested tuple ⇒ depth > MAX_NESTING.
        let mut s = String::from("f(");
        for _ in 0..9 {
            s.push('(');
        }
        s.push_str("uint256");
        for _ in 0..9 {
            s.push(')');
        }
        s.push(')');
        assert!(parse_text_sig(s.as_bytes()).is_none());
    }

    /// Round-trip every entry in secure/data/selectors.json against the
    /// firmware-side parser. Mirrors the gate the Python curator
    /// applies, so any drift (e.g. firmware accepting more or fewer
    /// types) trips this test loudly. Run as part of
    /// `cargo test -p sphincs-tz-secure --tests`.
    #[test]
    fn round_trip_curated_selectors_json() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/data/selectors.json");
        let text = std::fs::read_to_string(path)
            .expect("selectors.json missing — run `make selectors-json`?");
        let mut count = 0usize;
        let mut failed: Vec<String> = Vec::new();
        for sig in iter_text_sigs(&text) {
            count += 1;
            if parse_text_sig(sig.as_bytes()).is_none() {
                failed.push(sig.to_string());
                if failed.len() >= 10 {
                    break;
                }
            }
        }
        assert!(count > 0, "no entries scanned in selectors.json");
        assert!(
            failed.is_empty(),
            "parser rejected {} curator-accepted entries (showing up to 10): {:?}",
            failed.len(),
            failed,
        );
    }

    /// Trivial JSON-line scanner: yields every value of the
    /// "text_sig": "..." key. Avoids pulling serde_json into
    /// dev-dependencies for a one-shot fixture.
    fn iter_text_sigs(text: &str) -> impl Iterator<Item = &str> {
        text.lines().filter_map(|line| {
            let key = "\"text_sig\":";
            let i = line.find(key)?;
            let rest = &line[i + key.len()..];
            let q1 = rest.find('"')?;
            let after = &rest[q1 + 1..];
            let q2 = after.find('"')?;
            Some(&after[..q2])
        })
    }
}
