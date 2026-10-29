#![no_std]
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

pub struct Observation {
    pub byte: u8,
    pub emitted: usize,
    pub residual: usize,
    pub calls: usize,
}

// Only the initialized-entry component is studied here. No claim about the
// original GenericArray default/generate/partially initialized builder follows.
pub fn observe_step(
    initial: [u8; 64], pos: usize, input: &[u8], probe: usize,
    before: [u8; 8], after: [u8; 8],
) -> Observation {
    assert!(pos < 64 && input.len() <= 192);
    let total = pos + input.len();
    assert!(if total == 0 { probe == 0 } else { probe < total });
    // SAFETY: the exact source-pinned Buffer<U64,Eager> has only a u8
    // position, GenericArray<u8,U64> (u8 leaves and ZSTs), and PhantomData.
    // All-zero bytes form a valid zero-position object, independently of field
    // layout. Public set then installs arbitrary initialized bytes/position.
    let mut buffer: Buffer = unsafe { core::mem::zeroed() };
    buffer.set(*GenericArray::<u8, U64>::from_slice(&initial), pos);
    let mut frame = Frame { before, buffer, after };
    let mut emitted = 0usize;
    let mut calls = 0usize;
    let mut seen = 0usize;
    let mut byte = 0u8;
    // Observe one universally quantified position without constructing a
    // second full trace inside the symbolic harness. No hash result is stubbed.
    frame.buffer.digest_blocks(input, |blocks| {
        assert!(!blocks.is_empty());
        let next = emitted + blocks.len() * 64;
        if probe >= emitted && probe < next {
            let offset = probe - emitted;
            byte = blocks[offset / 64][offset % 64];
            seen += 1;
        }
        emitted = next;
        calls += 1;
    });
    let residual = frame.buffer.get_pos();
    assert!(emitted == total / 64 * 64);
    assert!(residual == total % 64);
    assert!(calls <= 2);
    assert!((calls == 0) == (total < 64));
    if total > 0 {
        if probe < emitted {
            assert!(seen == 1);
        } else {
            assert!(seen == 0);
            byte = frame.buffer.get_data()[probe - emitted];
        }
        let expected = if probe < pos { initial[probe] } else { input[probe - pos] };
        assert!(byte == expected);
    } else {
        assert!(seen == 0);
    }
    for i in 0..8 {
        assert!(frame.before[i] == before[i]);
        assert!(frame.after[i] == after[i]);
    }
    Observation { byte, emitted, residual, calls }
}

#[cfg(kani)]
mod symbolic {
    use super::*;

    #[kani::proof]
    #[kani::unwind(257)]
    fn original_initialized_step() {
        let initial: [u8; 64] = kani::any();
        let input: [u8; 192] = kani::any();
        let pos: usize = kani::any();
        let len: usize = kani::any();
        let probe: usize = kani::any();
        let before: [u8; 8] = kani::any();
        let after: [u8; 8] = kani::any();
        kani::assume(pos < 64 && len <= 192);
        let total = pos + len;
        kani::assume(if total == 0 { probe == 0 } else { probe < total });
        let _ = observe_step(initial, pos, &input[..len], probe, before, after);
        kani::cover!(pos == 0 && len == 0, "empty update");
        kani::cover!(pos == 63 && len == 0, "buffered empty update");
        kani::cover!(pos == 1 && len == 62, "no compression");
        kani::cover!(pos == 1 && len == 63, "exact fill");
        kani::cover!(pos == 63 && len == 192, "three blocks and residual");
    }
}
