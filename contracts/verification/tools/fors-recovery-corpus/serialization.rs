// Inputs use position-dependent bytes; expected outputs are independently
// concatenated fields, compared to unchanged inline production fragments.
fn serialization_byte(case: usize, domain: usize, i: usize) -> u8 {
    (17 * i + 29 * (i / 16) + 43 * case + 61 * domain) as u8
}
fn serialization_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn sign_serialization_corpus() {
    let counts = [0, 255, 256, 65535, 65536, 0x12345678, 0x80000000, u32::MAX];
    let offsets = [0, 1, 2336, 3172, 7, 2336, 3172, 3172];
    let mut out = String::from("-- Independent concatenation oracle versus unchanged production writer fragments.\nnamespace SignSerializationDiff\nstructure Vector where\n  pattern : Nat\n  offset : Nat\n  count : Nat\n  forest : String\n  layer : String\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for case in 0..counts.len() {
        let initial = std::array::from_fn(|i| serialization_byte(case, 0, i));
        let secrets = std::array::from_fn(|t| std::array::from_fn(|i| serialization_byte(case, 1, t*16+i)));
        let paths = std::array::from_fn(|t| std::array::from_fn(|h| std::array::from_fn(|i| serialization_byte(case, 2, (t*11+h)*16+i))));
        let chains = std::array::from_fn(|t| std::array::from_fn(|i| serialization_byte(case, 3, t*16+i)));
        let auth = std::array::from_fn(|h| std::array::from_fn(|i| serialization_byte(case, 4, h*16+i)));
        let (forest, forest_offset) = serialization_forest_fragment(&initial, &secrets, &paths);
        let mut forest_expected = initial[..16].to_vec();
        forest_expected.extend(secrets.iter().flatten().copied());
        forest_expected.extend(paths.iter().flatten().flatten().copied());
        forest_expected.extend_from_slice(&initial[2336..]);
        assert_eq!(forest_offset, 2336);
        assert_eq!(forest.as_slice(), forest_expected);
        let base = offsets[case];
        let count = counts[case];
        let (layer, layer_offset) = serialization_layer_fragment(&initial, base, &chains, count, &auth);
        let mut layer_expected = initial[..base].to_vec();
        layer_expected.extend(chains.iter().flatten().copied());
        // Independent arithmetic encoding of all four bytes.
        layer_expected.extend([((count as u64 / 16777216) % 256) as u8,
            ((count as u64 / 65536) % 256) as u8, ((count as u64 / 256) % 256) as u8, (count % 256) as u8]);
        layer_expected.extend(auth.iter().flatten().copied());
        layer_expected.extend_from_slice(&initial[base+836..]);
        assert_eq!(layer_offset, base+836);
        assert_eq!(layer.as_slice(), layer_expected);
        assert_eq!(u32::from_be_bytes(layer[base+688..base+692].try_into().unwrap()), count);
        out.push_str(&format!("{{ pattern := {case}, offset := {base}, count := {count}, forest := \"{}\", layer := \"{}\" }},\n", serialization_hex(&forest_expected), serialization_hex(&layer_expected)));
    }
    out.push_str("]\nend SignSerializationDiff\n");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extracted/Extracted/SignSerializationDiffVectors.lean");
    if std::env::var("PQ_SIGN_SERIALIZATION_GENERATE").as_deref() == Ok("1") {
        std::fs::write(path, out).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(path).unwrap(), out, "serialization corpus drift");
    }
}
