fn main() {
    // the vendored protoc, so that the project builds wherever it is moved
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("no vendored protoc for this platform");
    // SAFETY: build scripts are single-threaded
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::configure().compile_protos(&["proto/mlsbond.proto"], &["proto"]).expect("cannot compile proto/mlsbond.proto");
}
