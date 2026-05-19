//! libFuzzer harness for the ERC-7730 renderer dispatch path
//! (Phase 5 item 9).
//!
//! The full renderer (`secure/src/tx/display/erc7730/`) depends on
//! hardware-only `crate::ui::*` bindings and cannot be linked from
//! the `pqsigner-fuzz` host crate. The dispatch path that IS
//! reachable — descriptor IR parse → `find_format_by_selector` →
//! per-format field iteration — lives in `pqsigner-erc7730`
//! (a host-runnable workspace crate) and that's what this harness
//! drives.
//!
//! Coverage gap: the per-formatter Pages emission (formatters.rs
//! dispatch) is NOT exercised here. Tracking item: move `Pages` out
//! of the `#[cfg(not(test))]`-gated `tx::display` tree so the
//! formatter dispatch can be host-linked. Until then this harness
//! catches descriptor-side DoS panics (the format-iterator already
//! has prior bug history — see `tests/erc7730_walker.rs` regression
//! tests in this crate); the on-device formatter side is exercised
//! through the QEMU `make e2e` Scenario 5m + 5p paths.
//!
//! Strategy: take the first 4 bytes of `data` as the would-be
//! calldata selector, the next 4 bytes as a per-format selector
//! variant, and use the remainder as raw IR bytes fed to
//! `Erc7730Ir::parse`. The parser MUST be panic-free for any input;
//! a successful parse then drives `find_format_by_selector` against
//! BOTH selectors (so both the "match" and "no match" branches get
//! hit) and walks the field iter of every format header to expose
//! any field-table walk-off.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::ir::Erc7730Ir;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let Ok(selector_a) = <[u8; 4]>::try_from(&data[..4]) else {
        return;
    };
    let Ok(selector_b) = <[u8; 4]>::try_from(&data[4..8]) else {
        return;
    };
    let ir_bytes = &data[8..];

    // 1. Parse — must never panic, even on adversarial bytes.
    let Ok(ir) = Erc7730Ir::parse(ir_bytes) else {
        return;
    };

    // 2. Both selectors drive the dispatch path. selector_a is the
    //    "calldata selector" the renderer would receive from the
    //    inbound transaction; selector_b is a second arbitrary
    //    selector to probe the "no match" branch even when
    //    selector_a happens to collide.
    let _ = ir.find_format_by_selector(&selector_a);
    let _ = ir.find_format_by_selector(&selector_b);

    // 3. Walk every format header's field list. This is the path the
    //    renderer takes after locating the format — `format.fields()`
    //    iterates the field-table bytes and must be walk-off-safe.
    for fmt_result in ir.format_iter() {
        let Ok(fmt) = fmt_result else {
            continue;
        };
        for field_result in fmt.fields() {
            let _ = field_result;
        }
    }
});
