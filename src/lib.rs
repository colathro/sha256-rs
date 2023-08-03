const SHA256_CONSTANTS: &[u32] = &[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct SHA256 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
}

impl SHA256 {
    pub fn new() -> SHA256 {
        SHA256 {
            h0: 0x6a09e667,
            h1: 0xbb67ae85,
            h2: 0x3c6ef372,
            h3: 0xa54ff53a,
            h4: 0x510e527f,
            h5: 0x9b05688c,
            h6: 0x1f83d9ab,
            h7: 0x5be0cd19,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut buf: Vec<u8> = bytes.clone().into();

        // Pre-processing (Padding):
        buf.push(0x80);

        while ((buf.len() * 8) + 64) % 512 != 0 {
            buf.push(0x0);
        }

        let bytes_len_in_bits = (bytes.len() as u64) * 8;
        for i in (0..8).rev() {
            buf.push(((bytes_len_in_bits >> (i * 8)) & 0xFF) as u8);
        }

        // Process the message in successive 512-bit chunks:
        for chunk in buf.chunks(64) {
            // create a 64-entry message schedule array w[0..63] of 32-bit words
            let mut w: [u32; 64] = [0; 64];
            // (The initial values in w[0..63] don't matter, so many implementations zero them here)

            // copy chunk into first 16 words w[0..15] of the message schedule array
            let mut w_ind = 0;
            for sub_chunk in chunk.chunks(4) {
                w[w_ind] = ((sub_chunk[0] as u32) << 24)
                    + ((sub_chunk[1] as u32) << 16)
                    + ((sub_chunk[2] as u32) << 8)
                    + ((sub_chunk[3] as u32) << 0);
                w_ind += 1;
            }

            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
            for i in 16..64 {
                let s0 =
                    w[i - 15].rotate_right(7) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // Initialize working variables to current hash value:
            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;
            let mut f = self.h5;
            let mut g = self.h6;
            let mut h = self.h7;

            // Compression function main loop:
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

                let ch = (e & f) ^ (!e & g);

                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA256_CONSTANTS[i])
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

            // Add the compressed chunk to the current hash value:
            self.h0 = self.h0.wrapping_add(a);
            self.h1 = self.h1.wrapping_add(b);
            self.h2 = self.h2.wrapping_add(c);
            self.h3 = self.h3.wrapping_add(d);
            self.h4 = self.h4.wrapping_add(e);
            self.h5 = self.h5.wrapping_add(f);
            self.h6 = self.h6.wrapping_add(g);
            self.h7 = self.h7.wrapping_add(h);
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut digest: [u8; 32] = [0; 32];
        let mut digest_ind = 0;

        for byte in self.h0.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h1.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h2.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h3.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h4.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h5.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h6.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        for byte in self.h7.to_be_bytes() {
            digest[digest_ind] = byte;
            digest_ind += 1;
        }

        return digest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn empty() {
        let mut hash = SHA256::new();
        hash.update(&[]);
        let digest = hash.digest();
        let hex_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let expected_bytes = <[u8; 32]>::from_hex(hex_str).expect("Decoding failed");
        assert_eq!(digest, expected_bytes);
    }

    #[test]
    fn small_nums() {
        let mut hash = SHA256::new();
        hash.update("123456".as_bytes());
        let digest = hash.digest();
        let hex_str = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
        let expected_bytes = <[u8; 32]>::from_hex(hex_str).expect("Decoding failed");
        assert_eq!(digest, expected_bytes);
    }

    #[test]
    fn long_letters() {
        let mut hash = SHA256::new();
        hash.update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes());
        let digest = hash.digest();
        let hex_str = "135f63b80716c256810d20d2e6d3ff4bbb08f99ecdce1ba89eb8885e8937a513";
        let expected_bytes = <[u8; 32]>::from_hex(hex_str).expect("Decoding failed");
        assert_eq!(digest, expected_bytes);
    }
}
