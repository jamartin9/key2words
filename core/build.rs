fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=sequoia-time.patch");
    cargo_patch::patch().expect("Failed while patching");
}
