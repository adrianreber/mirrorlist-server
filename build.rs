extern crate protobuf_codegen;

fn main() {
    protobuf_codegen::Codegen::new()
        .out_dir("src/bin/common/protos")
        .inputs(["protos/mirrormanager.proto"])
        .include("protos")
        .run_from_script();
}
