fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell cargo about the rust_analyzer cfg
    println!("cargo::rustc-check-cfg=cfg(rust_analyzer)");

    // Generate to both OUT_DIR (for cargo build) and src/generated (for rust-analyzer)
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| "src".to_string());

    tonic_build::configure()
        .out_dir(&out_dir)
        .file_descriptor_set_path(format!("{}/auth_descriptor.bin", out_dir))
        .compile_protos(&["proto/auth.proto"], &["proto"])?;

    // Also generate to src/generated for rust-analyzer
    if std::env::var("OUT_DIR").is_ok() {
        std::fs::create_dir_all("src/generated")?;
        tonic_build::configure()
            .out_dir("src/generated")
            .file_descriptor_set_path("src/generated/auth_descriptor")
            .compile_protos(&["proto/auth.proto"], &["proto"])?;
    }
    Ok(())
}
