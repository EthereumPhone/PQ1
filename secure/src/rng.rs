//! Platform-agnostic RNG facade.
//!
//! On QEMU: delegates to `host_rng` (semihosting /dev/urandom).
//! On STM32U585: delegates to `hw::rng` (hardware TRNG peripheral).

#[cfg(not(feature = "stm32u585"))]
use crate::host_rng;
#[cfg(feature = "stm32u585")]
use crate::hw::rng as hw_rng;

pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::fill(buf) }
    #[cfg(feature = "stm32u585")]
    { hw_rng::fill(buf) }
}

pub fn byte() -> u8 {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::byte() }
    #[cfg(feature = "stm32u585")]
    { hw_rng::byte() }
}
