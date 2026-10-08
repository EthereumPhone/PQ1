// Add a test child to the actual private-helper module without editing it.
// The production module's full source bytes are inserted unchanged.
use std::{env, fs, path::PathBuf};
fn main() {
    let base = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = base.join("../../../../sphincs-c10/src/hypertree.rs");
    let corpus = base.join("corpus.rs");
    let forest = base.join("forest.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", corpus.display());
    let body = fs::read_to_string(source).unwrap();
    println!("cargo:rerun-if-changed={}", forest.display());
    let tests = fs::read_to_string(corpus).unwrap() + "\n" + &fs::read_to_string(forest).unwrap();
    let output =
        format!("mod hypertree {{\n{body}\n#[cfg(test)] mod recovery_corpus {{\n{tests}\n}}\n}}\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("production.rs"),
        output,
    )
    .unwrap();
}
