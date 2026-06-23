use std::env;

fn main() {
    let app_name = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "Termul Rust App".to_string());
    println!("=======================================");
    println!(" Welcome to {}!", app_name);
    println!(" Created with Termul Manager");
    println!("=======================================");
    println!("Running in target directory: {:?}", env::current_dir().unwrap());
}
