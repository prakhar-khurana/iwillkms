fn main() {
    println!("cargo:rerun-if-changed=src/parser/scl.pest");
}