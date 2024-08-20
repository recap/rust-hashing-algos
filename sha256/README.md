# SHA-256 Implementation in Rust

This repository contains a basic implementation of the SHA-256 cryptographic hash function in Rust. The implementation is educational, with detailed inline documentation comments explaining each step of the algorithm.

## Overview

SHA-256 (Secure Hash Algorithm 256-bit) is a member of the SHA-2 cryptographic hash functions family, widely used in security protocols, digital signatures, and blockchain technology. It produces a fixed-size 256-bit (32-byte) hash value from input data of any size.

This implementation is designed to help you understand the internal workings of the SHA-256 algorithm.

## Features

- **State Initialization**: Initializes the internal state with SHA-256-specific constants.
- **Update Function**: Allows incremental feeding of data into the hash function.
- **Padding and Finalizing**: Pads the input data and processes the final block to produce the hash.
- **Block Processing**: Handles the core 64-round compression function of the SHA-256 algorithm.

## Usage

To use the SHA-256 implementation:

```bash
echo -n "hello world" | cargo run --
```

## Code Explanation

### `struct Sha256`

The `Sha256` struct encapsulates the state and logic of the SHA-256 algorithm:

- **`state: [u32; 8]`**: Holds the current state of the hash, consisting of eight 32-bit words (H0, H1, ..., H7). These are initialized to specific constants based on the fractional parts of the square roots of the first eight primes.
- **`count: u64`**: Tracks the total number of bits processed so far. This is used to correctly pad the final block.
- **`buffer: [u8; 64]`**: A 64-byte buffer that temporarily holds data until it can be processed in full 512-bit (64-byte) chunks.

### `fn new() -> Sha256`

The `new` function initializes the SHA-256 state:

- Initializes the state with predefined constants.
- Sets the bit count to zero.
- Initializes the buffer to hold up to 64 bytes of data.

### `fn process_block(&mut self)`

The `process_block` function handles the core computation of SHA-256:

- **Message Schedule (`w`)**: Expands the 512-bit block into 64 words.
- **Compression Function**: Iteratively processes the expanded block using bitwise operations and modular addition, updating the state.

### `fn update(&mut self, data: &[u8])`

The `update` function feeds data into the hash function:

- Appends data to the buffer.
- Processes full blocks when available, leaving partial blocks in the buffer for future processing.

### `fn finalize(mut self) -> [u8; 32]`

The `finalize` function completes the hash computation:

- Pads the final block according to the SHA-256 specification.
- Processes the last block and produces the final hash value as a 32-byte array.

## Example Code

```rust
fn main() {
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    let result = hasher.finalize();

    for byte in &result {
        print!("{:02x}", byte);
    }
    println!();
}
```

## External links:

- Detailed video: [https://www.youtube.com/watch?v=orIgy2MjqrA](https://www.youtube.com/watch?v=orIgy2MjqrA)

## Important Notes

**Educational Use Only**: This implementation is designed for learning purposes and is **not** optimized for performance or security. For real-world applications, consider using well-tested cryptographic libraries.

## License

This project is licensed under the APACHE 2 License. See the [LICENSE](../LICENSE) file for details.
