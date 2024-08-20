# SHA-1 Implementation in Rust

This repository contains a basic implementation of the SHA-1 cryptographic hash function in Rust. The implementation is educational and provides a step-by-step explanation of the SHA-1 algorithm with detailed inline documentation comments.

## Overview

SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit hash value (20 bytes). It is widely used in various security applications and protocols, including TLS and SSL, PGP, SSH, and IPsec. However, due to vulnerabilities discovered over time, it is no longer considered secure for most cryptographic purposes, and its use is generally discouraged in favor of stronger hash functions like SHA-256.

This implementation serves as an educational resource to understand how the SHA-1 algorithm works under the hood.

## Features

- **State Initialization**: Initializes the internal state with SHA-1-specific constants.
- **Update Function**: Allows feeding data into the hash function incrementally.
- **Padding and Finalizing**: Pads the input data to ensure its length is a multiple of 512 bits and finalizes the hash computation.
- **Chunk Processing**: Processes each 512-bit chunk of data through the core SHA-1 compression function.

## Usage

To use the SHA-1 implementation:

```bash
echo -n "hello world" | cargo run --
```

## Code Explanation

The core implementation is encapsulated in the `Sha1` struct, which contains the following key components:

### `state: [u32; 5]`

An array holding the internal state of the hash, consisting of five 32-bit words (160 bits in total). This state is initialized with specific constants as defined in the SHA-1 specification.

### `data: Vec<u8>`

A buffer that accumulates the input data until it can be processed in 512-bit (64-byte) chunks. Any leftover data after processing is retained in this buffer.

### `bit_len: u64`

Tracks the total length of the input data in bits. This value is used during the padding process to finalize the hash computation.

### `fn update(&mut self, input: &[u8])`

Feeds input data into the hash function. This method appends the data to the internal buffer and processes any complete 512-bit chunks.

### `fn digest(mut self) -> [u8; 20]`

Finalizes the hash computation by applying padding and processing any remaining chunks. The method returns the resulting 160-bit (20-byte) SHA-1 hash as an array of bytes.

### `fn process_chunk(&mut self, chunk: &[u8])`

The core of the SHA-1 algorithm. This function processes a single 512-bit chunk of data, performing 80 rounds of operations that update the internal state based on the input data.

## Example Code

```rust
fn main() {
    let mut hasher = Sha1::new();
    hasher.update(b"The quick brown fox jumps over the lazy dog");
    let result = hasher.digest();

    for byte in &result {
        print!("{:02x}", byte);
    }
    println!();
}
```

## Important Notes

**Educational Use Only**: This implementation is designed for learning purposes and is **not** optimized for performance or security. For real-world applications, consider using well-tested cryptographic libraries.

## License

This project is licensed under the APACHE 2 License. See the [LICENSE](../LICENSE) file for details.
