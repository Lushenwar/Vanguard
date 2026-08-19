//! Protobuf codegen for the control plane.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `protoc` is not on the PATH on every developer machine, and asking each
    // one to install a system package to build the crate is a worse trade than
    // vendoring the binary the build already knows how to fetch.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    println!("cargo:rerun-if-changed=src/api/proto/vanguard.proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["src/api/proto/vanguard.proto"], &["src/api/proto"])?;
    Ok(())
}
