//! Authenticated topology and exact interval partition for bounded multi-tail
//! contract calldata.
//!
//! The descriptor compiler derives [`TailTopology`] from the complete canonical
//! function signature. The Merkle-rooted payload is therefore trusted metadata;
//! the calldata body remains fully adversarial. [`validate_exact_partition`]
//! accepts only when two to four top-level dynamic objects form one canonical,
//! ordered tiling of every byte after the authenticated static head.
//!
//! This is deliberately not a generic ABI walker. It understands only the two
//! top-level object geometries authorized by the schema: `bytes`/`string` blobs
//! and dynamic arrays whose elements are one static ABI word. Field renderers
//! consume the resulting intervals by authenticated head slot instead of
//! following offsets independently.

use core::convert::TryFrom;

use pqsigner_tx::typed_call::abi::{read_length_word, read_offset_word, MAX_DYNAMIC_LEN};

use super::{resolve::canonical_blob_bounds, RenderErr};

/// Version byte of the authenticated topology payload.
pub const TOPOLOGY_VERSION: u8 = 1;
/// Smallest topology that grants multi-tail authority.
pub const MIN_DYNAMIC_TAILS: usize = 2;
/// Maximum authenticated top-level tails in one format.
pub const MAX_DYNAMIC_TAILS: usize = 4;
/// Maximum calldata body after the four-byte selector. Follows the per-call
/// cap (8188 since `MAX_TX_LEN` went to 8192 on 2026-10-22): a verified,
/// request-bound descriptor hard-refuses on any `RenderErr`, so a stale
/// literal here would refuse every 4-8 KB call such a descriptor covers.
pub const MAX_MULTI_TAIL_BODY_LEN: usize = pqsigner_proto::MAX_TX_LEN - 4;

const TOPOLOGY_HEADER_LEN: usize = 2;
const TOPOLOGY_RECORD_LEN: usize = 3;

/// Authenticated ABI geometry of one top-level dynamic object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TailKind {
    /// Solidity `bytes` or `string`: byte length followed by zero right-padding.
    Blob = 1,
    /// Solidity `T[]` where `T` occupies exactly one static 32-byte ABI word.
    StaticWordArray = 2,
}

/// Stable wire byte for a Solidity `bytes` or `string` tail.
pub const TAIL_KIND_BLOB: u8 = TailKind::Blob as u8;
/// Stable wire byte for a dynamic array of one-word static ABI elements.
pub const TAIL_KIND_STATIC_WORD_ARRAY: u8 = TailKind::StaticWordArray as u8;

impl TailKind {
    /// Stable authenticated wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TailKind {
    type Error = RenderErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Blob),
            2 => Ok(Self::StaticWordArray),
            _ => Err(RenderErr::Reject("7730 topology kind")),
        }
    }
}

/// One authenticated topology record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailTopologyRecord {
    /// Static-head word containing this object's ABI offset.
    pub slot: u16,
    /// Geometry used to interpret the object's length word.
    pub kind: TailKind,
}

const EMPTY_RECORD: TailTopologyRecord = TailTopologyRecord {
    slot: 0,
    kind: TailKind::Blob,
};

/// Parsed, fixed-capacity authenticated topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailTopology {
    records: [TailTopologyRecord; MAX_DYNAMIC_TAILS],
    count: u8,
}

impl TailTopology {
    /// Parse `version | count | count * (slot:u16 BE | kind:u8)` exactly.
    ///
    /// Count, record order, uniqueness, kinds, and trailing bytes are checked
    /// here. Call [`Self::validate_static_head`] once the enclosing format's
    /// authenticated `static_head_words` is available.
    pub fn parse(payload: &[u8]) -> Result<Self, RenderErr> {
        let header = payload
            .get(..TOPOLOGY_HEADER_LEN)
            .ok_or(RenderErr::Reject("7730 topology short"))?;
        if header[0] != TOPOLOGY_VERSION {
            return Err(RenderErr::Reject("7730 topology version"));
        }
        let count = header[1] as usize;
        if !(MIN_DYNAMIC_TAILS..=MAX_DYNAMIC_TAILS).contains(&count) {
            return Err(RenderErr::Reject("7730 topology count"));
        }
        let expected_len = TOPOLOGY_HEADER_LEN
            .checked_add(
                count
                    .checked_mul(TOPOLOGY_RECORD_LEN)
                    .ok_or(RenderErr::Reject("7730 topology overflow"))?,
            )
            .ok_or(RenderErr::Reject("7730 topology overflow"))?;
        if payload.len() != expected_len {
            return Err(RenderErr::Reject("7730 topology length"));
        }

        let mut records = [EMPTY_RECORD; MAX_DYNAMIC_TAILS];
        let mut previous_slot: Option<u16> = None;
        for (index, record) in records.iter_mut().take(count).enumerate() {
            let start = TOPOLOGY_HEADER_LEN
                .checked_add(
                    index
                        .checked_mul(TOPOLOGY_RECORD_LEN)
                        .ok_or(RenderErr::Reject("7730 topology overflow"))?,
                )
                .ok_or(RenderErr::Reject("7730 topology overflow"))?;
            let bytes = payload
                .get(start..start + TOPOLOGY_RECORD_LEN)
                .ok_or(RenderErr::Reject("7730 topology record"))?;
            let slot = u16::from_be_bytes([bytes[0], bytes[1]]);
            if previous_slot.is_some_and(|previous| slot <= previous) {
                return Err(RenderErr::Reject("7730 topology slot order"));
            }
            *record = TailTopologyRecord {
                slot,
                kind: TailKind::try_from(bytes[2])?,
            };
            previous_slot = Some(slot);
        }

        Ok(Self {
            records,
            count: count as u8,
        })
    }

    /// Require every authenticated offset-word slot to lie inside the complete
    /// static ABI head.
    pub fn validate_static_head(&self, static_head_words: u16) -> Result<(), RenderErr> {
        for record in self.records() {
            if record.slot >= static_head_words {
                return Err(RenderErr::Reject("7730 topology slot outside head"));
            }
        }
        Ok(())
    }

    /// Number of authenticated records (`2..=4`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// A topology is never empty after successful parsing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Canonical records in top-level ABI argument order.
    #[must_use]
    pub fn records(&self) -> &[TailTopologyRecord] {
        &self.records[..self.len()]
    }

    /// Record at an authenticated ordinal.
    #[must_use]
    pub fn record(&self, index: usize) -> Option<TailTopologyRecord> {
        self.records().get(index).copied()
    }
}

/// Exact half-open geometry of one authenticated tail object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailInterval {
    pub slot: u16,
    pub kind: TailKind,
    /// Start of the object's 32-byte length/count word.
    pub object_start: usize,
    /// First declared blob byte or first array element word.
    pub data_start: usize,
    /// Exclusive end of declared blob bytes or array element words.
    pub data_end: usize,
    /// Exclusive end of the complete object, including blob right-padding.
    pub object_end: usize,
    /// Blob byte length or static-word array element count.
    pub count: u32,
}

impl TailInterval {
    /// Borrow the exact declared data interval from the body, excluding a blob's
    /// length word and right-padding.
    pub fn data<'a>(&self, body: &'a [u8]) -> Result<&'a [u8], RenderErr> {
        if self.object_start > self.data_start
            || self.data_start > self.data_end
            || self.data_end > self.object_end
            || self.object_end > body.len()
        {
            return Err(RenderErr::Reject("7730 partition interval"));
        }
        body.get(self.data_start..self.data_end)
            .ok_or(RenderErr::Reject("7730 partition data"))
    }
}

const EMPTY_INTERVAL: TailInterval = TailInterval {
    slot: 0,
    kind: TailKind::Blob,
    object_start: 0,
    data_start: 0,
    data_end: 0,
    object_end: 0,
    count: 0,
};

/// Fixed-copy proof that the authenticated objects exactly tile the body tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailPartition {
    intervals: [TailInterval; MAX_DYNAMIC_TAILS],
    count: u8,
    head_end: usize,
    body_end: usize,
}

impl TailPartition {
    /// Number of proven intervals.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Exact end of the authenticated static head and start of the first tail.
    #[must_use]
    pub const fn head_end(&self) -> usize {
        self.head_end
    }

    /// Exact end of the final tail and of the complete calldata body.
    #[must_use]
    pub const fn body_end(&self) -> usize {
        self.body_end
    }

    /// Proven intervals in canonical top-level argument order.
    #[must_use]
    pub fn intervals(&self) -> &[TailInterval] {
        &self.intervals[..self.len()]
    }

    /// Find exactly one interval by authenticated head slot and geometry.
    /// Returns its topology ordinal together with a copy of the interval.
    pub fn find(&self, slot: usize, kind: TailKind) -> Result<(usize, TailInterval), RenderErr> {
        let slot = u16::try_from(slot).map_err(|_| RenderErr::Reject("7730 partition slot"))?;
        for (index, interval) in self.intervals().iter().copied().enumerate() {
            if interval.slot == slot {
                if interval.kind != kind {
                    return Err(RenderErr::Reject("7730 partition kind"));
                }
                return Ok((index, interval));
            }
        }
        Err(RenderErr::Reject("7730 partition missing slot"))
    }
}

/// Establish one exact canonical partition for every authenticated topology
/// record. No field-local resolver may broaden the intervals returned here.
pub fn validate_exact_partition(
    topology: &TailTopology,
    body: &[u8],
    static_head_words: u16,
) -> Result<TailPartition, RenderErr> {
    topology.validate_static_head(static_head_words)?;
    if body.len() > MAX_MULTI_TAIL_BODY_LEN {
        return Err(RenderErr::Reject("7730 partition body cap"));
    }
    if body.len() % 32 != 0 {
        return Err(RenderErr::Reject("7730 partition unaligned body"));
    }
    let head_end = usize::from(static_head_words)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 partition head overflow"))?;
    if head_end > body.len() {
        return Err(RenderErr::Reject("7730 partition short head"));
    }

    let mut intervals = [EMPTY_INTERVAL; MAX_DYNAMIC_TAILS];
    let mut cursor = head_end;
    for (index, record) in topology.records().iter().copied().enumerate() {
        let word_start = usize::from(record.slot)
            .checked_mul(32)
            .ok_or(RenderErr::Reject("7730 partition slot overflow"))?;
        let word_end = word_start
            .checked_add(32)
            .ok_or(RenderErr::Reject("7730 partition slot overflow"))?;
        let offset_word = body
            .get(word_start..word_end)
            .ok_or(RenderErr::Reject("7730 partition offset word"))?;
        let actual_offset =
            read_offset_word(offset_word).ok_or(RenderErr::Reject("7730 partition offset"))?;
        if actual_offset != cursor {
            return Err(RenderErr::Reject("7730 partition cursor"));
        }

        let interval = match record.kind {
            TailKind::Blob => {
                let bounds = canonical_blob_bounds(body, cursor)?;
                TailInterval {
                    slot: record.slot,
                    kind: record.kind,
                    object_start: cursor,
                    data_start: bounds.data_start,
                    data_end: bounds.data_end,
                    object_end: bounds.padded_end,
                    count: bounds.len,
                }
            }
            TailKind::StaticWordArray => {
                let length_end = cursor
                    .checked_add(32)
                    .ok_or(RenderErr::Reject("7730 partition array overflow"))?;
                let count_word = body
                    .get(cursor..length_end)
                    .ok_or(RenderErr::Reject("7730 partition array count"))?;
                let count = read_length_word(count_word)
                    .ok_or(RenderErr::Reject("7730 partition array count"))?;
                if count > MAX_DYNAMIC_LEN {
                    return Err(RenderErr::Reject("7730 partition array cap"));
                }
                let data_len = usize::try_from(count)
                    .ok()
                    .and_then(|value| value.checked_mul(32))
                    .ok_or(RenderErr::Reject("7730 partition array overflow"))?;
                let data_end = length_end
                    .checked_add(data_len)
                    .ok_or(RenderErr::Reject("7730 partition array overflow"))?;
                body.get(length_end..data_end)
                    .ok_or(RenderErr::Reject("7730 partition array data"))?;
                TailInterval {
                    slot: record.slot,
                    kind: record.kind,
                    object_start: cursor,
                    data_start: length_end,
                    data_end,
                    object_end: data_end,
                    count,
                }
            }
        };
        if interval.object_end > body.len() || interval.object_end % 32 != 0 {
            return Err(RenderErr::Reject("7730 partition object end"));
        }
        intervals[index] = interval;
        cursor = interval.object_end;
    }

    if cursor != body.len() {
        return Err(RenderErr::Reject("7730 partition trailing"));
    }
    Ok(TailPartition {
        intervals,
        count: topology.len() as u8,
        head_end,
        body_end: cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const BLOB_BLOB: [u8; 8] = [1, 2, 0, 0, 1, 0, 1, 1];

    fn put_word(body: &mut [u8], offset: usize, value: u32) {
        body[offset + 28..offset + 32].copy_from_slice(&value.to_be_bytes());
    }

    fn two_blob_body(first: &[u8], second: &[u8]) -> Vec<u8> {
        let first_padded = (first.len() + 31) / 32 * 32;
        let second_padded = (second.len() + 31) / 32 * 32;
        let first_start = 64;
        let second_start = first_start + 32 + first_padded;
        let mut body = vec![0u8; second_start + 32 + second_padded];
        put_word(&mut body, 0, first_start as u32);
        put_word(&mut body, 32, second_start as u32);
        put_word(&mut body, first_start, first.len() as u32);
        body[first_start + 32..first_start + 32 + first.len()].copy_from_slice(first);
        put_word(&mut body, second_start, second.len() as u32);
        body[second_start + 32..second_start + 32 + second.len()].copy_from_slice(second);
        body
    }

    #[test]
    fn topology_parser_is_exact_and_head_bounded() {
        let topology = TailTopology::parse(&BLOB_BLOB).unwrap();
        assert_eq!(topology.len(), 2);
        assert_eq!(topology.record(0).unwrap().slot, 0);
        assert_eq!(topology.record(1).unwrap().kind, TailKind::Blob);
        assert_eq!(topology.validate_static_head(2), Ok(()));
        assert!(topology.validate_static_head(1).is_err());

        for malformed in [
            &[2, 2, 0, 0, 1, 0, 1, 1][..],    // version
            &[1, 1, 0, 0, 1][..],             // below count floor
            &[1, 5][..],                      // above count cap
            &[1, 2, 0, 0, 1, 0, 0, 1][..],    // duplicate slot
            &[1, 2, 0, 1, 1, 0, 0, 1][..],    // descending slot
            &[1, 2, 0, 0, 3, 0, 1, 1][..],    // unknown kind
            &[1, 2, 0, 0, 1, 0, 1][..],       // truncated
            &[1, 2, 0, 0, 1, 0, 1, 1, 0][..], // trailing
        ] {
            assert!(TailTopology::parse(malformed).is_err());
        }
    }

    #[test]
    fn blob_blob_partition_tiles_exactly_and_lookup_binds() {
        let topology = TailTopology::parse(&BLOB_BLOB).unwrap();
        let body = two_blob_body(b"abc", b"");
        let partition = validate_exact_partition(&topology, &body, 2).unwrap();
        assert_eq!(partition.len(), 2);
        assert_eq!(partition.head_end(), 64);
        assert_eq!(partition.body_end(), body.len());
        let (first_index, first) = partition.find(0, TailKind::Blob).unwrap();
        let (second_index, second) = partition.find(1, TailKind::Blob).unwrap();
        assert_eq!((first_index, second_index), (0, 1));
        assert_eq!(first.object_start, 64);
        assert_eq!(first.data(&body).unwrap(), b"abc");
        assert_eq!(first.object_end, second.object_start);
        assert_eq!(second.data(&body).unwrap(), b"");
        assert_eq!(second.object_end, body.len());
        assert!(partition.find(0, TailKind::StaticWordArray).is_err());
        assert!(partition.find(2, TailKind::Blob).is_err());
    }

    #[test]
    fn mixed_blob_and_two_arrays_partition() {
        let payload = [1, 3, 0, 0, 1, 0, 1, 2, 0, 2, 2];
        let topology = TailTopology::parse(&payload).unwrap();
        // head(96), blob("x") -> 64 B, array(2) -> 96 B, array(0) -> 32 B.
        let mut body = vec![0u8; 288];
        put_word(&mut body, 0, 96);
        put_word(&mut body, 32, 160);
        put_word(&mut body, 64, 256);
        put_word(&mut body, 96, 1);
        body[128] = b'x';
        put_word(&mut body, 160, 2);
        body[192 + 31] = 7;
        body[224 + 31] = 9;
        put_word(&mut body, 256, 0);

        let partition = validate_exact_partition(&topology, &body, 3).unwrap();
        assert_eq!(partition.len(), 3);
        assert_eq!(partition.find(0, TailKind::Blob).unwrap().1.count, 1);
        let array = partition.find(1, TailKind::StaticWordArray).unwrap().1;
        assert_eq!(array.count, 2);
        assert_eq!(array.data(&body).unwrap().len(), 64);
        assert_eq!(
            partition
                .find(2, TailKind::StaticWordArray)
                .unwrap()
                .1
                .count,
            0
        );
    }

    #[test]
    fn adjacent_empty_tails_are_canonical() {
        let topology = TailTopology::parse(&BLOB_BLOB).unwrap();
        let body = two_blob_body(b"", b"");
        let partition = validate_exact_partition(&topology, &body, 2).unwrap();
        assert_eq!(partition.intervals()[0].object_start, 64);
        assert_eq!(partition.intervals()[0].object_end, 96);
        assert_eq!(partition.intervals()[1].object_start, 96);
        assert_eq!(partition.intervals()[1].object_end, 128);
    }

    #[test]
    fn partition_rejects_alias_gap_reorder_padding_truncation_and_suffix() {
        let topology = TailTopology::parse(&BLOB_BLOB).unwrap();
        let canonical = two_blob_body(b"abc", b"z");

        let mut alias = canonical.clone();
        put_word(&mut alias, 32, 64);
        assert!(validate_exact_partition(&topology, &alias, 2).is_err());

        let mut gap = canonical.clone();
        put_word(&mut gap, 32, 160);
        assert!(validate_exact_partition(&topology, &gap, 2).is_err());

        let mut reordered = canonical.clone();
        put_word(&mut reordered, 0, 128);
        assert!(validate_exact_partition(&topology, &reordered, 2).is_err());

        let mut dirty_high = canonical.clone();
        dirty_high[0] = 1;
        assert!(validate_exact_partition(&topology, &dirty_high, 2).is_err());

        let mut dirty_padding = canonical.clone();
        dirty_padding[99] = 1;
        assert!(validate_exact_partition(&topology, &dirty_padding, 2).is_err());

        assert!(
            validate_exact_partition(&topology, &canonical[..canonical.len() - 32], 2).is_err()
        );

        let mut trailing = canonical.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert!(validate_exact_partition(&topology, &trailing, 2).is_err());

        assert!(validate_exact_partition(&topology, &canonical[..canonical.len() - 1], 2).is_err());
        // The body cap itself: one word past the per-call cap is refused by the
        // cap, before any alignment or tail work.
        assert!(matches!(
            validate_exact_partition(&topology, &[0u8; pqsigner_proto::MAX_TX_LEN], 2),
            Err(RenderErr::Reject("7730 partition body cap"))
        ));
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    const TWO_BLOBS: [u8; 8] = [1, 2, 0, 0, 1, 0, 1, 1];

    #[kani::proof]
    #[kani::unwind(40)]
    fn accepted_partition_exactly_tiles_and_binds() {
        let body: [u8; 192] = kani::any();
        let topology = TailTopology::parse(&TWO_BLOBS).unwrap();
        if let Ok(partition) = validate_exact_partition(&topology, &body, 2) {
            assert!(partition.len() == 2);
            let first = partition.intervals()[0];
            let second = partition.intervals()[1];
            assert!(partition.head_end() == 64);
            assert!(first.object_start == 64);
            assert!(first.object_end == second.object_start);
            assert!(second.object_end == body.len());
            assert!(partition.body_end() == body.len());
            assert!(first.data_start >= first.object_start + 32);
            assert!(first.data_end <= first.object_end);
            assert!(second.data_start >= second.object_start + 32);
            assert!(second.data_end <= second.object_end);
        }
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn partition_lookup_binds_slot_kind_and_index() {
        let body: [u8; 192] = kani::any();
        let topology = TailTopology::parse(&TWO_BLOBS).unwrap();
        if let Ok(partition) = validate_exact_partition(&topology, &body, 2) {
            let slot: usize = kani::any();
            if let Ok((index, interval)) = partition.find(slot, TailKind::Blob) {
                assert!(index < partition.len());
                assert!(interval == partition.intervals()[index]);
                assert!(usize::from(interval.slot) == slot);
                assert!(interval.kind == TailKind::Blob);
            }
            assert!(partition.find(0, TailKind::StaticWordArray).is_err());
            assert!(partition.find(1, TailKind::StaticWordArray).is_err());
        }
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn concrete_two_empty_blobs_is_nonvacuous() {
        let topology = TailTopology::parse(&TWO_BLOBS).unwrap();
        let mut body = [0u8; 128];
        body[31] = 64;
        body[63] = 96;
        let partition = validate_exact_partition(&topology, &body, 2)
            .expect("canonical adjacent empty blobs must be accepted");
        assert!(partition.intervals()[0].object_end == 96);
        assert!(partition.intervals()[1].object_end == 128);
    }

    #[kani::proof]
    fn body_cap_is_enforced_before_tail_work() {
        let topology = TailTopology::parse(&TWO_BLOBS).unwrap();
        let body = [0u8; pqsigner_proto::MAX_TX_LEN];
        assert!(validate_exact_partition(&topology, &body, 2).is_err());
    }
}
