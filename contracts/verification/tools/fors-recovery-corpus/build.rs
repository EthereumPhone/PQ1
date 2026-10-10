// Add a test child to the actual private-helper module without editing it.
// The production module's full source bytes are inserted unchanged.
use std::{env, fs, path::PathBuf};
fn main() {
    let base = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = base.join("../../../../sphincs-c10/src/hypertree.rs");
    let corpus = base.join("corpus.rs");
    let forest = base.join("forest.rs");
    let prefix = base.join("prefix.rs");
    let continuation = base.join("continuation.rs");
    let whole = base.join("whole.rs");
    let keygen = base.join("keygen.rs");
    let roundtrip = base.join("roundtrip.rs");
    let xmssroot = base.join("xmssroot.rs");
    let xmssauth = base.join("xmssauth.rs");
    let wotssign = base.join("wotssign.rs");
    let shuffle = base.join("shuffle.rs");
    let signforest = base.join("signforest.rs");
    let serialization = base.join("serialization.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", corpus.display());
    let body = fs::read_to_string(source).unwrap();
    println!("cargo:rerun-if-changed={}", forest.display());
    println!("cargo:rerun-if-changed={}", prefix.display());
    println!("cargo:rerun-if-changed={}", continuation.display());
    println!("cargo:rerun-if-changed={}", whole.display());
    println!("cargo:rerun-if-changed={}", keygen.display());
    println!("cargo:rerun-if-changed={}", roundtrip.display());
    println!("cargo:rerun-if-changed={}", xmssroot.display());
    println!("cargo:rerun-if-changed={}", xmssauth.display());
    println!("cargo:rerun-if-changed={}", wotssign.display());
    println!("cargo:rerun-if-changed={}", shuffle.display());
    println!("cargo:rerun-if-changed={}", signforest.display());
    println!("cargo:rerun-if-changed={}", serialization.display());
    // Execute the exact unchanged inline writer fragments with arbitrary fields.
    // Keep the complete production module above; these test-only wrappers expose
    // inputs that a whole signature's bounded grinder does not readily produce.
    fn fragment<'a>(body: &'a str, start: &str, end: &str) -> &'a str {
        assert_eq!(body.matches(start).count(), 1, "ambiguous serializer start");
        assert_eq!(body.matches(end).count(), 1, "ambiguous serializer end");
        body.split_once(start).unwrap().1.split_once(end).unwrap().0
    }
    let forest_fragment = fragment(&body, "    // Write ALL secrets (K * N bytes).", "    // Compute FORS public key");
    let layer_fragment = fragment(&body, "        // Write WOTS chain values (L * N bytes)", "        // Compute the reconstructed root for the next layer");
    let serializers = format!(r#"
fn serialization_forest_fragment(initial: &[u8; SIGNATURE_LEN], fors_secrets: &[[u8; N]; K],
    fors_auth_paths: &[[[u8; N]; A]; K-1]) -> ([u8; SIGNATURE_LEN], usize) {{
    let mut sig = *initial;
    let mut offset = N;
    // Write ALL secrets (K * N bytes).{forest_fragment}
    (sig, offset)
}}
fn serialization_layer_fragment(initial: &[u8; SIGNATURE_LEN], initial_offset: usize,
    wots_sigma: &[[u8; N]; L], count: u32, auth_path: &[[u8; N]; SUBTREE_H]) -> ([u8; SIGNATURE_LEN], usize) {{
    let mut sig = *initial;
    let mut offset = initial_offset;
    {layer_fragment}
    (sig, offset)
}}
"#);
    let tests = fs::read_to_string(corpus).unwrap()
        + "\n"
        + &fs::read_to_string(forest).unwrap()
        + "\n"
        + &fs::read_to_string(prefix).unwrap()
        + "\n"
        + &fs::read_to_string(continuation).unwrap()
        + "\n"
        + &fs::read_to_string(whole).unwrap()
        + "\n"
        + &fs::read_to_string(keygen).unwrap()
        + "\n"
        + &fs::read_to_string(roundtrip).unwrap()
        + "\n"
        + &fs::read_to_string(xmssroot).unwrap()
        + "\n"
        + &fs::read_to_string(xmssauth).unwrap()
        + "\n"
        + &fs::read_to_string(wotssign).unwrap()
        + "\n"
        + &fs::read_to_string(shuffle).unwrap()
        + "\n"
        + &fs::read_to_string(signforest).unwrap()
        + "\n"
        + &serializers
        + "\n"
        + &fs::read_to_string(serialization).unwrap();
    let output =
        format!("mod hypertree {{\n{body}\n#[cfg(test)] mod recovery_corpus {{\n{tests}\n}}\n}}\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("production.rs"),
        output,
    )
    .unwrap();
}
