//! ISO 7816-4 BER-TLV utilities — pure functions, no hardware deps.
//!
//! Both the SE050 driver (`crate::se050::apdu`) and any other ISO
//! 7816-4 consumer (e.g. the OPTIGA path's PIN counter responses)
//! ultimately decode the same length-prefixed `(tag, length, value)`
//! shape. Pulling that decode + encode logic out of `se050::apdu.rs`
//! into this module buys two things:
//!
//!   * The pure functions are always-on (not gated behind the `se050`
//!     feature), so they participate in `cargo test` host runs and can
//!     be hammered by the proptest harness in `crate::fuzz_props`.
//!   * Every consumer reads the SAME parser, so a fuzz failure here
//!     surfaces in EVERY caller's flow — no quietly forked decoders.
//!
//! Wire-format reference: ISO 7816-4 §5.2.2 + GP Card Spec 2.3 §11.
//!
//! Length encoding:
//!   * `len < 0x80`           → single short-form byte
//!   * `0x81 <byte>`          → 1-byte length, value 0..=255
//!   * `0x82 <hi> <lo>`       → 2-byte length, value 0..=65535
//!
//! Anything else (multi-byte length > 2 bytes, indefinite length 0x80,
//! truncation) is rejected. The decoder is total: it returns
//! `Option<(tag, value, rest)>` rather than panicking on bad input.

/// Encode a TLV into `buf` at `offset`. Returns the new offset (i.e.
/// the position one past the last written byte).
///
/// Panics under `debug_assertions` if the resulting offset would
/// overrun `buf`. Production callers always use a fixed-size APDU
/// builder buffer; the encoder assumes the caller pre-sized that
/// buffer correctly. This matches the previous `se050::apdu::tlv_put`
/// behaviour byte-for-byte.
pub fn tlv_put(buf: &mut [u8], offset: usize, tag: u8, value: &[u8]) -> usize {
    let mut o = offset;
    buf[o] = tag;
    o += 1;
    let len = value.len();
    if len < 0x80 {
        buf[o] = len as u8;
        o += 1;
    } else if len < 0x100 {
        buf[o] = 0x81;
        buf[o + 1] = len as u8;
        o += 2;
    } else {
        buf[o] = 0x82;
        buf[o + 1] = (len >> 8) as u8;
        buf[o + 2] = (len & 0xFF) as u8;
        o += 3;
    }
    buf[o..o + len].copy_from_slice(value);
    o + len
}

/// Encode a 4-byte big-endian object ID as TLV.
pub fn tlv_put_u32(buf: &mut [u8], offset: usize, tag: u8, val: u32) -> usize {
    tlv_put(buf, offset, tag, &val.to_be_bytes())
}

/// Parse the first TLV from `data`. Returns `(tag, value, rest)`.
///
/// Returns `None` on:
///   * empty / 1-byte input (no room for tag + length)
///   * truncated long-form length (0x81 with no follow byte, 0x82 with
///     fewer than 2 follow bytes)
///   * any length encoding other than short / 0x81 / 0x82 (e.g. 0x83
///     would imply 3 length bytes — out of scope)
///   * declared length running past `data.len()`
///
/// The decoder is panic-free for any input slice — proven by the
/// `tlv_parse_never_panics` proptest harness in `fuzz_props`.
pub fn tlv_parse(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (len, hdr): (usize, usize) = if data[1] < 0x80 {
        (data[1] as usize, 2)
    } else if data[1] == 0x81 && data.len() >= 3 {
        (data[2] as usize, 3)
    } else if data[1] == 0x82 && data.len() >= 4 {
        (((data[2] as usize) << 8) | data[3] as usize, 4)
    } else {
        return None;
    };
    let end = hdr.checked_add(len)?;
    if data.len() < end {
        return None;
    }
    Some((tag, &data[hdr..end], &data[end..]))
}

/// Parse an OPTIGA UPCTR `(current, limit)` 8-byte object: two
/// big-endian u32s. Returns `None` on wrong length. Same wire format
/// as the gated `optiga::apdu::parse_pin_ctr`.
pub fn parse_pin_ctr(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() != 8 {
        return None;
    }
    let current = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let limit = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    Some((current, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_put_short() {
        let mut buf = [0u8; 16];
        let n = tlv_put(&mut buf, 0, 0x41, &[1, 2, 3]);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], &[0x41, 0x03, 1, 2, 3]);
    }

    #[test]
    fn tlv_put_long() {
        let mut buf = [0u8; 300];
        let v = [0xABu8; 200];
        let n = tlv_put(&mut buf, 0, 0x42, &v);
        assert_eq!(n, 3 + 200);
        assert_eq!(buf[0], 0x42);
        assert_eq!(buf[1], 0x81);
        assert_eq!(buf[2], 200);
    }

    #[test]
    fn tlv_parse_round_trip() {
        let mut buf = [0u8; 16];
        let n = tlv_put(&mut buf, 0, 0x41, &[1, 2, 3]);
        let (tag, val, rest) = tlv_parse(&buf[..n]).unwrap();
        assert_eq!(tag, 0x41);
        assert_eq!(val, &[1, 2, 3]);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_parse_truncated_short() {
        // Tag + claimed length 5, but only 3 bytes follow.
        assert!(tlv_parse(&[0x41, 0x05, 1, 2, 3]).is_none());
    }

    #[test]
    fn tlv_parse_truncated_long_81() {
        assert!(tlv_parse(&[0x41, 0x81]).is_none());
    }

    #[test]
    fn tlv_parse_truncated_long_82() {
        assert!(tlv_parse(&[0x41, 0x82, 0x00]).is_none());
    }

    #[test]
    fn tlv_parse_unsupported_long_form_83() {
        // 0x83 would imply 3 length bytes — not handled; we reject.
        assert!(tlv_parse(&[0x41, 0x83, 0, 0, 1, 1]).is_none());
    }

    #[test]
    fn parse_pin_ctr_basic() {
        let bytes = [0, 0, 0, 7, 0, 0, 0, 10];
        let (current, limit) = parse_pin_ctr(&bytes).unwrap();
        assert_eq!(current, 7);
        assert_eq!(limit, 10);
    }

    #[test]
    fn parse_pin_ctr_wrong_length() {
        assert!(parse_pin_ctr(&[]).is_none());
        assert!(parse_pin_ctr(&[0; 7]).is_none());
        assert!(parse_pin_ctr(&[0; 9]).is_none());
    }
}
