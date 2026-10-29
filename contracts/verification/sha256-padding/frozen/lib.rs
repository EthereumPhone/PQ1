#![no_std]
#![allow(deprecated)]

use block_buffer::EagerBuffer;
use generic_array::{typenum::U64, GenericArray};

// Calls the original registry implementation, without a stub or a modified
// dependency. The arbitrary bytes include the unused tail of the input buffer.
pub fn original_padding(initial: [u8; 64], pos: usize, bit_len: u64)
    -> ([[u8; 64]; 2], usize, usize)
{
    let mut buffer = EagerBuffer::<U64>::default();
    let block: GenericArray<u8, U64> = unsafe { core::mem::transmute(initial) };
    buffer.set(block, pos);
    let mut blocks = [[0u8; 64]; 2];
    let mut count = 0usize;
    buffer.len64_padding_be(bit_len, |block| {
        assert!(count < 2);
        blocks[count].copy_from_slice(block.as_slice());
        count += 1;
    });
    (blocks, count, buffer.get_pos())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // This proves the finite host Kani memory-model contract. It does not
    // establish Rust retag/alias semantics or a cross-tool Aeneas refinement.
    fn check(single: bool) {
        let initial: [u8; 64] = kani::any();
        let pos: usize = kani::any();
        let bit_len: u64 = kani::any();
        kani::assume(pos < 64);
        kani::assume((pos < 56) == single);
        let (blocks, count, final_pos) = original_padding(initial, pos, bit_len);
        assert!(count == if single { 1 } else { 2 });
        assert!(final_pos == 0);
        // Independent positional specification. The suffix is specified using
        // shifts, not the to_be_bytes method used by the original implementation.
        for i in 0..64 {
            let first = if single && i >= 56 {
                (bit_len >> (8 * (63 - i))) as u8
            } else if i < pos {
                initial[i]
            } else if i == pos {
                0x80
            } else {
                0
            };
            assert!(blocks[0][i] == first);
            let second = if !single && i >= 56 {
                (bit_len >> (8 * (63 - i))) as u8
            } else {
                0
            };
            assert!(blocks[1][i] == second);
        }
        if single {
            kani::cover!(pos == 0, "empty partial block");
            kani::cover!(pos == 55, "last one-block position");
        } else {
            kani::cover!(pos == 56, "first two-block position");
            kani::cover!(pos == 63, "last two-block position");
        }
        kani::cover!(bit_len == u64::MAX, "all length bits set");
        kani::cover!(bit_len == 0, "zero encoded length");
    }

    #[kani::proof]
    #[kani::unwind(65)]
    fn padding_single_block() { check(true); }

    #[kani::proof]
    #[kani::unwind(65)]
    fn padding_two_blocks() { check(false); }
}
