use glob::glob;
use protobuf_codegen::Codegen;

fn main() {
    Codegen::new()
        .pure()
        .cargo_out_dir("proto")
        .inputs(
            glob("proto/*.proto")
                .expect("Failed to read glob pattern")
                .flat_map(|result| match result {
                    Ok(path) => Some(path),
                    Err(e) => {
                        println!("Failed to read glob pattern: {e}");
                        None
                    }
                }),
        )
        .include("proto/")
        .run_from_script();
}
