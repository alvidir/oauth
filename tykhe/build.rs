use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // compiling protos using path on build time
    tonic_build::compile_protos("../proto/user.proto")?;
    tonic_build::compile_protos("../proto/session.proto")?;

    Ok(())
}
