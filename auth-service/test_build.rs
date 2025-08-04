fn main() -> Result<(), Box<dyn std::error::Error>> { println!("Building proto files..."); tonic_build::compile_protos("proto/auth.proto")?; println!("Proto files generated successfully!"); Ok(()) }
