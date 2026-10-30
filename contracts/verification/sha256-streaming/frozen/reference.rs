#![allow(dead_code)]
#![allow(deprecated)]

use block_buffer::{BlockBuffer, Eager};
use generic_array::{typenum::U64, GenericArray};

type Buffer = BlockBuffer<U64, Eager>;

#[repr(C)]
struct Frame {
    before: [u8; 8],
    buffer: Buffer,
    after: [u8; 8],
}

// Research entry state only: this does NOT verify BlockBuffer::default/new or
// GenericArray's partially initialized builder. The exact pinned Buffer has
// only a GenericArray<u8,U64>, a u8 position and zero-sized PhantomData<Eager>.
// The exact GenericArray tree contains only initialized u8 leaves and ZSTs.
// Thus all-zero bytes give a valid value with position 0; no layout order is
// assumed. set() then supplies an arbitrary fully initialized buffer and pos.
fn initialized_frame(initial: [u8; 64], pos: usize) -> Frame {
    assert!(pos < 64);
    // SAFETY: the field/type validity argument above applies only to the exact
    // source-pinned u8/U64/Eager instantiation, not arbitrary Buffer/Array types.
    let mut buffer: Buffer = unsafe { core::mem::zeroed() };
    buffer.set(*GenericArray::<u8, U64>::from_slice(&initial), pos);
    Frame { before: [0x4b; 8], buffer, after: [0xb4; 8] }
}

pub fn full_trace(initial: [u8; 64], pos: usize, input: &[u8]) -> ([u8; 256], usize, usize, usize) {
    assert!(pos < 64 && input.len() <= 192);
    let mut frame = initialized_frame(initial, pos);
    let mut emitted = [0u8; 256];
    let mut emitted_len = 0usize;
    let mut calls = 0usize;
    // The production dependency's method is called directly. This callback
    // observes its complete emitted-byte trace; it does not emulate SHA-256.
    frame.buffer.digest_blocks(input, |blocks| {
        assert!(!blocks.is_empty(), "empty compression callback");
        calls += 1;
        for block in blocks {
            emitted[emitted_len..emitted_len + 64].copy_from_slice(block);
            emitted_len += 64;
        }
    });
    let total = pos + input.len();
    assert_eq!(emitted_len, total / 64 * 64, "emitted length");
    assert_eq!(frame.buffer.get_pos(), total % 64, "residual length");
    assert!(calls <= 2, "callback count");
    assert_eq!(calls == 0, total < 64, "callback reachability");
    for i in 0..total {
        let expected = if i < pos { initial[i] } else { input[i - pos] };
        let actual = if i < emitted_len {
            emitted[i]
        } else {
            frame.buffer.get_data()[i - emitted_len]
        };
        assert_eq!(actual, expected, "stream byte order");
    }
    assert_eq!(frame.before, [0x4b; 8], "prefix frame");
    assert_eq!(frame.after, [0xb4; 8], "suffix frame");
    emitted[emitted_len..total].copy_from_slice(frame.buffer.get_data());
    (emitted, emitted_len, frame.buffer.get_pos(), calls)
}

pub fn check_two_steps(initial: [u8; 64], pos: usize, first: &[u8], second: &[u8]) {
    assert!(pos < 64 && first.len() <= 192 && second.len() <= 192);
    let mut frame = initialized_frame(initial, pos);
    let mut emitted = [0u8; 448];
    let mut emitted_len = 0usize;
    for input in [first, second] {
        frame.buffer.digest_blocks(input, |blocks| {
            assert!(!blocks.is_empty(), "empty compression callback");
            for block in blocks {
                emitted[emitted_len..emitted_len + 64].copy_from_slice(block);
                emitted_len += 64;
            }
        });
    }
    let total = pos + first.len() + second.len();
    assert_eq!(emitted_len, total / 64 * 64, "emitted length");
    assert_eq!(frame.buffer.get_pos(), total % 64, "residual length");
    for i in 0..total {
        let expected = if i < pos {
            initial[i]
        } else if i < pos + first.len() {
            first[i - pos]
        } else {
            second[i - pos - first.len()]
        };
        let actual = if i < emitted_len {
            emitted[i]
        } else {
            frame.buffer.get_data()[i - emitted_len]
        };
        assert_eq!(actual, expected, "stream byte order");
    }
    assert_eq!(frame.before, [0x4b; 8], "prefix frame");
    assert_eq!(frame.after, [0xb4; 8], "suffix frame");
}

