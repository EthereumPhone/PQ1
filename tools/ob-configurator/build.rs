fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::copy("memory.x", format!("{out_dir}/memory.x")).unwrap();
    println!("cargo:rustc-link-search={out_dir}");
    println!("cargo:rerun-if-changed=memory.x");
}
