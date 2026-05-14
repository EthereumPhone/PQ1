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
//! | 0x3D | `nested_callee`      | 20 B address                               |
//! | 0x3E | `fallback_label`     | ASCII (≤254 B)                             |
//! | 0x3F | `visibility`         | 1 B (Visibility byte value), optionally    |
//! |      |                      | followed by a Phase 5 value-list sub-TLV.  |
//!
//! Wire-stable.
//!
//! Unknown tags are rejected — a hostile descriptor that smuggles an
//! unknown tag must NOT silently render: it might describe semantics
//! the renderer can't honour.

use crate::tx::erc7730::{Erc7730Ir, Visibility};

use super::RenderErr;

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
    pub nested_callee: Option<&'a [u8; 20]>,
    pub fallback_label: Option<&'a [u8]>,
    /// Always populated. Defaults to `Always` when no VISIBILITY TLV is
    /// present.
    pub visibility: Visibility,
    /// Sub-TLV for `IfNotIn` / `MustMatch` value lists (Phase 5+).
    /// Phase 4 only sees this when the VISIBILITY TLV's payload is
    /// longer than 1 byte; current `dbgen` only emits a 1-byte payload.
    pub visibility_values: Option<&'a [u8]>,
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
            visibility: Visibility::Always,
            visibility_values: None,
        }
    }
}

/// Parse a TLV parameter blob located at `param_off` inside the IR's
/// metadata pool. Returns the default [`ParamSet`] (everything `None`,
/// visibility `Always`) when `param_off == 0`.
pub fn parse<'a>(
    ir: &Erc7730Ir<'a>,
    param_off: u16,
) -> Result<ParamSet<'a>, RenderErr> {
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

        match tag {
            PARAM_TOKEN_PATH => p.token_path = Some(payload),
            PARAM_TOKEN => {
                p.token = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad token"))?,
                );
            }
            PARAM_THRESHOLD => {
                p.threshold = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad threshold"))?,
                );
            }
            PARAM_MESSAGE => p.message = Some(payload),
            PARAM_ADDR_TYPES => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad addr-types"));
                }
                p.addr_types = Some(payload[0]);
            }
            PARAM_ADDR_SOURCES => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad addr-sources"));
                }
                p.addr_sources = Some(payload[0]);
            }
            PARAM_DATE_ENCODING => {
                if payload.len() != 1 {
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
            PARAM_BASE => p.base = Some(payload),
            PARAM_PREFIX => {
                if payload.len() != 1 {
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
                        .map_err(|_| RenderErr::Reject("7730 bad nested callee"))?,
                );
            }
            PARAM_FALLBACK_LABEL => p.fallback_label = Some(payload),
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

    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::erc7730::{Erc7730Ir, Visibility, HEADER_LEN, SCHEMA_VER};

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
    fn parses_visibility_never() {
        let pool = std::vec![0xFFu8, 3, 0x3F, 0x01, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::Never);
        assert!(p.visibility_values.is_none());
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
        let mut pool = std::vec![0xFFu8, 254, PARAM_MESSAGE, 252];
        pool.extend_from_slice(&[0x41u8; 252]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.message.map(|m| m.len()), Some(252));
    }

    #[test]
    fn parses_nested_selector_and_callee() {
        // For the Calldata formatter the descriptor supplies the
        // expected inner selector + callee address.
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_NESTED_SELECTOR, 0x04, 0xa9, 0x05, 0x9c, 0xbb]);
        body.extend_from_slice(&[PARAM_NESTED_CALLEE, 0x14]);
        body.extend_from_slice(&[0xDD; 20]);
        let mut pool = std::vec![0xFFu8, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.nested_selector, Some(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(p.nested_callee, Some(&[0xDD; 20]));
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
}
