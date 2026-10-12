//! Test-only access to the unchanged private FORS recovery helper.
#![allow(dead_code)]
use sphincs_c10::{params, shuffle};
#[path = "../../../../../sphincs-c10/src/address.rs"]
mod address;
#[path = "../../../../../sphincs-c10/src/fors.rs"]
mod fors;
#[path = "../../../../../sphincs-c10/src/hash.rs"]
mod hash;
#[path = "../../../../../sphincs-c10/src/merkle.rs"]
mod merkle;
#[path = "../../../../../sphincs-c10/src/wots.rs"]
mod wots;
include!(concat!(env!("OUT_DIR"), "/production.rs"));
