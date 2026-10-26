// Proof-only module root for the exact pinned RustCrypto portable word kernel.
// The byte loop, Digest API, padding, dispatch and hardware are outside this root.
#![no_std]
#[path = "vendor/sha2-0.10.9/src/consts.rs"]
mod consts;
#[path = "vendor/sha2-0.10.9/src/sha256/soft.rs"]
mod soft;
