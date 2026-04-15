//! ARM assembly-backed Keccak-256 sponge.
//!
//! Uses the XKCP/Adomnicai assembly for the f1600 permutation and the
//! bit-interleaving absorb/squeeze helpers. The assembly state is 200
//! bytes in bit-interleaved form (50 × u32).

/// Minimal `Digest` trait matching the subset of `sha3::Digest` that
/// `sphincs-c7` and `jardin-fosc` use: `new()`, `update()`, `finalize()`.
pub trait Digest {
    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> [u8; 32];
}

extern "C" {
    fn KeccakP1600_Initialize(state: *mut u8);
    fn KeccakP1600_AddBytes(state: *mut u8, data: *const u8, offset: u32, length: u32);
    fn KeccakP1600_Permute_24rounds(state: *mut u8);
    fn KeccakP1600_ExtractBytes(state: *const u8, data: *mut u8, offset: u32, length: u32);
    #[allow(dead_code)]
    fn KeccakP1600_OverwriteWithZeroes(state: *mut u8, byte_count: u32);
}

/// Keccak-256 hasher backed by optimized ARMv7-M assembly.
///
/// Keccak-256 parameters: rate = 1088 bits (136 bytes), capacity = 512 bits,
/// output = 256 bits (32 bytes), padding = keccak (0x01), not SHA-3 (0x06).
pub struct Keccak256 {
    /// 200-byte state in bit-interleaved form (managed by assembly).
    state: [u8; 200],
    /// How many bytes have been absorbed into the current block.
    absorbed: usize,
}

/// Keccak-256 rate in bytes: (1600 - 512) / 8 = 136.
const RATE: usize = 136;

impl Digest for Keccak256 {
    #[inline]
    fn new() -> Self {
        let mut s = Keccak256 {
            state: [0u8; 200],
            absorbed: 0,
        };
        // SAFETY: state is a valid 200-byte buffer.
        unsafe { KeccakP1600_Initialize(s.state.as_mut_ptr()) };
        s
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        let mut offset = 0;
        let mut remaining = data.len();

        while remaining > 0 {
            let space = RATE - self.absorbed;
            let to_absorb = if remaining < space { remaining } else { space };

            // SAFETY: self.absorbed < RATE, to_absorb <= space, data is valid.
            unsafe {
                KeccakP1600_AddBytes(
                    self.state.as_mut_ptr(),
                    data.as_ptr().add(offset),
                    self.absorbed as u32,
                    to_absorb as u32,
                );
            }

            self.absorbed += to_absorb;
            offset += to_absorb;
            remaining -= to_absorb;

            if self.absorbed == RATE {
                // SAFETY: state is a valid 200-byte buffer.
                unsafe { KeccakP1600_Permute_24rounds(self.state.as_mut_ptr()) };
                self.absorbed = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        // Keccak padding (NOT SHA-3): pad with 0x01, then zeros, then 0x80
        // at position RATE-1.  The sha3 crate's Keccak256 uses domain
        // byte 0x01 (original Keccak), not 0x06 (FIPS 202 SHA-3).
        //
        // SAFETY: self.absorbed < RATE, state is valid.
        unsafe {
            // XOR padding byte 0x01 at current position
            let pad_byte: [u8; 1] = [0x01];
            KeccakP1600_AddBytes(
                self.state.as_mut_ptr(),
                pad_byte.as_ptr(),
                self.absorbed as u32,
                1,
            );

            // XOR 0x80 at position RATE-1
            let pad_end: [u8; 1] = [0x80];
            KeccakP1600_AddBytes(
                self.state.as_mut_ptr(),
                pad_end.as_ptr(),
                (RATE - 1) as u32,
                1,
            );

            // Final permutation
            KeccakP1600_Permute_24rounds(self.state.as_mut_ptr());
        }

        // Squeeze 32 bytes (output fits in a single block since 32 < RATE)
        let mut out = [0u8; 32];
        // SAFETY: state is valid, 32 < 200.
        unsafe {
            KeccakP1600_ExtractBytes(
                self.state.as_ptr(),
                out.as_mut_ptr(),
                0,
                32,
            );
        }
        out
    }
}

// Convenience: allow `Keccak256::new()` directly without importing Digest.
impl Keccak256 {
    /// Create a new Keccak-256 hasher.
    #[inline]
    pub fn new() -> Self {
        <Self as Digest>::new()
    }

    /// Absorb data into the sponge.
    #[inline]
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        <Self as Digest>::update(self, data)
    }

    /// Finalize and return the 32-byte digest.
    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        <Self as Digest>::finalize(self)
    }
}
