/// SHA-1 cryptographic hash function implementation in Rust
pub struct Sha1 {
    state: [u32; 5], // The internal state, holding five 32-bit words.
    data: Vec<u8>, // The data buffer, which accumulates input data until a full chunk (512 bits) is ready.
    bit_len: u64,  // The total length of the input data, in bits.
}

impl Sha1 {
    /// Creates a new SHA-1 instance with the initial state.
    pub fn new() -> Sha1 {
        // Initialize the state with SHA-1-specific constants.
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            data: Vec::new(), // Initialize the data buffer as empty.
            bit_len: 0,       // Initialize the bit length to zero.
        }
    }

    /// Updates the hash with new input data.
    ///
    /// # Arguments
    ///
    /// * `input` - A slice of bytes containing the data to be hashed.
    pub fn update(&mut self, input: &[u8]) {
        self.data.extend_from_slice(input); // Add the input data to the buffer.
        self.bit_len += (input.len() as u64) * 8; // Update the total bit length.

        // Process each 512-bit chunk as it becomes available.
        while self.data.len() >= 64 {
            let chunk = self.data.drain(..64).collect::<Vec<u8>>();
            self.process_chunk(&chunk); // Process the current chunk.
        }
    }

    /// Completes the hash computation and returns the final digest.
    ///
    /// # Returns
    ///
    /// A 20-byte array containing the SHA-1 hash.
    pub fn digest(mut self) -> [u8; 20] {
        // Padding: Start with a single '1' bit followed by '0' bits.
        let mut padding = vec![0x80];

        // Add '0' bits until the data size is congruent to 448 mod 512.
        while (self.data.len() + padding.len() + 8) % 64 != 0 {
            padding.push(0x00);
        }

        // Append the original message length as a 64-bit big-endian integer.
        self.data.append(&mut padding);
        self.data.extend_from_slice(&self.bit_len.to_be_bytes());

        // Process any remaining chunks after padding.
        while self.data.len() >= 64 {
            let chunk = self.data.drain(..64).collect::<Vec<u8>>();
            self.process_chunk(&chunk);
        }

        // Convert the internal state to a byte array for the final hash.
        let mut hash = [0u8; 20];
        for (i, &value) in self.state.iter().enumerate() {
            hash[i * 4..(i + 1) * 4].copy_from_slice(&value.to_be_bytes());
        }
        hash
    }

    /// Processes a single 512-bit chunk of data.
    ///
    /// # Arguments
    ///
    /// * `chunk` - A 64-byte array representing the current chunk of data.
    fn process_chunk(&mut self, chunk: &[u8]) {
        let mut w = [0u32; 80]; // Message schedule array, consisting of 80 32-bit words.

        // Prepare the message schedule w[0..16] from the chunk.
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        // Extend the first 16 words into the remaining 64 words of the message schedule.
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // Initialize the working variables with the current state.
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        // Main loop: Perform 80 rounds of operations.
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999), // Rounds 0-19
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),           // Rounds 20-39
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC), // Rounds 40-59
                _ => (b ^ c ^ d, 0xCA62C1D6),                 // Rounds 60-79
            };

            // Calculate the temporary value.
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d; // Move the working variables forward.
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Add the compressed chunk to the current hash value.
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}
