fn main() {
    #[cfg(feature = "eyra")]
    println!("cargo:rustc-link-arg=-nostartfiles");
}
