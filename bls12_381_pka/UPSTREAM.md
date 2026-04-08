# `bls12_381_pka` — vendored fork of `zkcrypto/bls12_381`

This crate is a vendored fork of the upstream [`bls12_381`](https://crates.io/crates/bls12_381)
crate (version **0.8.0**), renamed to `bls12_381_pka` and extended with a
single `pka` Cargo feature that hooks `Fp::mul` / `Fp::square` into the
STM32U585 PKA (Public-Key Accelerator) peripheral.

**Do not drop this in favour of the crates.io version without reviewing
the delta below.**

## Upstream baseline

* Crate: `bls12_381`
* Version: `0.8.0` (unmodified Cargo.toml metadata preserved in the fork)
* Repository: https://github.com/zkcrypto/bls12_381
* Tag to diff against: `0.8.0`
* License: MIT / Apache-2.0 (dual, unchanged)

The `Cargo.toml.orig` file Cargo leaves in the crate root is the
upstream-published `Cargo.toml` as of the 0.8.0 release; `Cargo.toml`
itself is the "normalised" post-publish version with our `pka`
feature appended.

## Local modifications

All changes are gated behind the `pka` feature, which is **off by
default**. Building without `pka` produces a crate that is
byte-identical in behaviour to upstream 0.8.0 (the file layout is
unchanged; only `#[cfg(feature = "pka")]` blocks are added). The `pka`
feature itself is declared in `Cargo.toml` as:

```toml
pka = []  # STM32U585 PKA hardware acceleration for Fp arithmetic
```

### `src/lib.rs`
* Adds `#![cfg_attr(not(feature = "pka"), deny(unsafe_code))]` at the
  crate root. Upstream has an unconditional `deny(unsafe_code)`; the
  PKA FFI hook requires `unsafe` so that attribute is relaxed ONLY
  when the `pka` feature is on. With the feature off, the crate
  still refuses to build with any `unsafe` code.

### `src/fp.rs`
* Adds `fn mul_pka(&self, rhs: &Fp) -> Fp`, which delegates
  Montgomery multiplication to a host-provided
  `bls12_381_pka_mont_mul(a: &[u32; 12], b: &[u32; 12]) -> [u32; 12]`
  hook declared via `extern "C"`. The expectation is that the firmware
  (see `secure/src/hw/pka.rs`) exports the symbol through
  `#[no_mangle]` / `#[export_name = "bls12_381_pka_mont_mul"]`.
* `Fp::mul` and `Fp::square` dispatch to the PKA path under
  `#[cfg(feature = "pka")]`, and fall back to the pure-software
  Montgomery multiplication (`mul_software`) otherwise.
* Adds `Fp -> [u32; 12]` / `[u32; 12] -> Fp` conversion helpers used
  by the PKA path.

### `src/fp2.rs`
* Minor `#[cfg(feature = "pka")]` guard on a single helper that
  short-circuits when PKA is available — see the top of the file
  for the exact sites.

Everything else under `src/` is unmodified.

## How to pull upstream changes

1. Fetch the upstream release you want to land on:
   ```bash
   git clone --depth 1 --branch <tag> https://github.com/zkcrypto/bls12_381 /tmp/bls12_381_upstream
   ```
2. Diff it against our tree to see what has changed upstream since
   0.8.0 (ignore the package-name rename from `bls12_381` →
   `bls12_381_pka`):
   ```bash
   diff -ruN --exclude=target --exclude=Cargo.lock \
       /tmp/bls12_381_upstream bls12_381_pka/
   ```
3. Apply the upstream diff by hand, preserving every
   `#[cfg(feature = "pka")]` block listed in this file.
4. Re-run the full test suite with `cargo test -p bls12_381_pka`
   (no feature flags) to confirm the software path is still
   byte-identical to upstream, then run `make e2e` and `make e2e-hw`
   to confirm the PKA path still produces correct BLS12-381 pairings
   on both QEMU (software fallback) and real STM32U585 (hardware
   accelerated).
5. Update the "Upstream baseline" section above with the new tag.

## Related code in the firmware

* `secure/src/hw/pka.rs` — STM32U585 PKA peripheral driver and the
  `bls12_381_pka_mont_mul` symbol that satisfies the extern above.
* `secure/Cargo.toml` — `pka-accel` feature wires `bls12_381/pka` on.
* `Makefile` — `run-hw` target enables `pka-accel,stm32u585`.
