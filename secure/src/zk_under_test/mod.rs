//! Test-only scaffold for the `secure-zk` slice.
//!
//! The production `zk` module at `crate::zk` is gated `#[cfg(not(test))]`
//! in `secure/src/main.rs` because its top-level `render_clear_sign_pages`
//! renderer transitively pulls `crate::tx::display` + `crate::ui` (both
//! also `cfg(not(test))`). The verifier *primitives* themselves —
//! `groth16.rs`, `poseidon.rs`, `vk_bundle.rs`, plus the top-level
//! verification entry points in `zk/mod.rs` — are pure logic and compile
//! cleanly on host.
//!
//! This scaffold re-mounts `zk/mod.rs` (and, through it, the three
//! child files via Rust's standard `pub mod child;` lookup relative to
//! the parent file's directory) under a parallel module tree, plus
//! sibling mounts for the otherwise-gated `test_vectors.rs` (gated
//! behind `feature = "debug-log"` in production) and the never-mounted
//! `vk_data.rs` (only consumed by `zk-test` on host today). The result
//! is a host-runnable view of every public symbol the slice exposes,
//! ready to be exercised from `pure_tests.rs`.

// Re-mount the entire `zk/mod.rs` under this scaffold. Its inner
// `pub mod groth16; pub mod poseidon; pub mod vk_bundle;` declarations
// resolve relative to `secure/src/zk/`, so the children are pulled in
// without any further `#[path]` plumbing. The `render_clear_sign_pages`
// fn stays `cfg(not(test))`-gated and is invisible here, which is
// exactly what we want — it depends on `crate::tx::display` /
// `crate::ui::*`, both of which are gated out under test.
#[path = "../zk/mod.rs"]
pub mod inner;

// `zk/test_vectors.rs` is gated behind `feature = "debug-log"` in
// production. Pull it in unconditionally under the test scaffold so
// the inventory of known-good (calldata, readable, proof, H_tx, H_str)
// vectors is available to assert against.
#[path = "../zk/test_vectors.rs"]
pub mod test_vectors;

// `zk/vk_data.rs` is never `mod`-mounted in production (the firmware
// receives VKs at runtime from the NS-supplied bundle, not from a
// baked-in array). Mount it here so the host-runnable Groth16
// positive-path test has a concrete 960-byte VK to feed the verifier.
#[path = "../zk/vk_data.rs"]
pub mod vk_data;

#[cfg(test)]
mod pure_tests;
