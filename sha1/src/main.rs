use sha1::Sha1;
use std::io::{self, Read};

fn main() {
    let mut hasher = Sha1::new();
    // Read data from standard input
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read input");

    // Update the hasher with the input data
    hasher.update(input.as_bytes());

    // Finalize the hash and print the result in hexadecimal format
    let hash = hasher.digest();
    for byte in &hash {
        print!("{:02x}", byte);
    }
    println!();
}
