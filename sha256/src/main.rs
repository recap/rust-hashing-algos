use sha256::Sha256;
use std::io::{self, Read};

fn main() {
    let mut hasher = Sha256::new();

    // Read data from standard input
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read input");

    // Update the hasher with the input data
    hasher.update(input.as_bytes());

    // Finalize the hash and print the result in hexadecimal format
    let hash = hasher.finalize();
    for byte in &hash {
        print!("{:02x}", byte);
    }
    println!();
}
