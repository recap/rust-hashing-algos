use std::io::{self, Read};

// SHA-256 structure containing the state, bit count, and a buffer for data
pub struct Sha256 {
    state: [u32; 8],  // Holds the current state of the hash (H0, H1, ..., H7)
    count: u64,       // Number of bits processed so far
    buffer: [u8; 64], // Buffer for holding partial blocks
}

impl Sha256 {
    // Constructor to initialize the SHA-256 state
    pub fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            count: 0,
            buffer: [0; 64],
        }
    }

    // Processes a 512-bit (64-byte) block of data
    fn process_block(&mut self) {
        let block = &self.buffer;
        assert!(block.len() == 64);

        // Prepare the message schedule (W)
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = ((block[4 * i] as u32) << 24)
                | ((block[4 * i + 1] as u32) << 16)
                | ((block[4 * i + 2] as u32) << 8)
                | (block[4 * i + 3] as u32);
        }

        // Extend the first 16 words into the remaining 48 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables with the current hash value
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Compression function main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Update the state with the new values
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    // Updates the hash state with a chunk of data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        let buffer_pos = (self.count as usize) % 64;
        self.count += (data.len() as u64) * 8;

        // If there's remaining data in the buffer, fill it and process the block
        if buffer_pos != 0 {
            let space_in_buffer = 64 - buffer_pos;
            if data.len() >= space_in_buffer {
                self.buffer[buffer_pos..].copy_from_slice(&data[..space_in_buffer]);
                self.process_block();
                data = &data[space_in_buffer..];
            } else {
                self.buffer[buffer_pos..buffer_pos + data.len()].copy_from_slice(data);
                return;
            }
        }

        // Process full blocks directly from the input data
        while data.len() >= 64 {
            self.buffer.copy_from_slice(&data[..64]);
            self.process_block();
            data = &data[64..];
        }

        // Store the remaining data in the buffer
        self.buffer[..data.len()].copy_from_slice(data);
    }

    // Finalizes the hash computation and returns the resulting 32-byte hash
    pub fn finalize(mut self) -> [u8; 32] {
        let mut buffer_pos = (self.count as usize / 8) % 64;
        self.buffer[buffer_pos] = 0x80; // Append the '1' bit to the end of the message
        buffer_pos += 1;

        // If there's not enough space for the length, pad the buffer and process it
        if buffer_pos > 56 {
            self.buffer[buffer_pos..].fill(0);
            self.process_block();
            self.buffer.fill(0);
        } else {
            self.buffer[buffer_pos..].fill(0);
        }

        // Append the bit count to the buffer and process the final block
        let bit_count = self.count.to_be_bytes();
        self.buffer[56..].copy_from_slice(&bit_count);
        self.process_block();

        // Convert the state to a byte array
        let mut result = [0u8; 32];
        for (i, &val) in self.state.iter().enumerate() {
            result[4 * i] = (val >> 24) as u8;
            result[4 * i + 1] = (val >> 16) as u8;
            result[4 * i + 2] = (val >> 8) as u8;
            result[4 * i + 3] = val as u8;
        }
        result
    }
}

// SHA-256 constants (K values)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

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
