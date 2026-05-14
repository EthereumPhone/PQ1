//! libFuzzer harness for `pqsigner_erc7730::ir::Erc7730Ir::parse` plus
//! the formats-section iterator. The IR parser is the on-device
//! validator for descriptor bytes that passed the Merkle check; a
//! parse-time panic would still be a denial-of-service vector and a
//! latent memory-safety risk. We exercise `parse` + drive the
//! `format_iter` to make every format-header / field-entry / pool
//! lookup byte traversable from corpus.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::ir::Erc7730Ir;

fuzz_target!(|data: &[u8]| {
    if let Ok(ir) = Erc7730Ir::parse(data) {
        // Walk every format header + every field entry so the parser
        // for the format-table sub-language is also covered.
        for fmt in ir.format_iter() {
            if let Ok(fmt) = fmt {
                for field in fmt.fields() {
                    let _ = field;
                }
            }
        }
        let _ = ir.format_count();
    }
});
