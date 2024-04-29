
/*

Pseudocode from https://en.wikipedia.org/wiki/SHA-2

Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380
*/

/*
Initialize array of round constants:
(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
*/
static K: [u32; 64] = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

struct Sha256State {
	hash: [u32; 8],
}

impl Sha256State {
	pub fn new() -> Self {
		Self {
			hash: [
				0x6a09e667_u32,
				0xbb67ae85_u32,
				0x3c6ef372_u32,
				0xa54ff53a_u32,
				0x510e527f_u32,
				0x9b05688c_u32,
				0x1f83d9ab_u32,
				0x5be0cd19_u32,
			]
		}
	}

	pub fn update(&mut self, chunk: &[u8; 64]) {
		/*
	    create a 64-entry message schedule array w[0..63] of 32-bit words
	    (The initial values in w[0..63] don't matter, so many implementations zero them here)
		*/
		let mut w = [0_u32; 64];
		/*
	    copy chunk into first 16 words w[0..15] of the message schedule array
		*/
		for (w, c) in w[0..16].iter_mut().zip(chunk.chunks_exact(4)) {
			*w = u32::from_be_bytes(c.try_into().unwrap());
		}

		/*
	    Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
	    for i from 16 to 63
	        s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
	        s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
	        w[i] := w[i-16] + s0 + w[i-7] + s1
		*/
		for i in 16..64 {
	        let s0 = w[i-15].rotate_right( 7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >>  3);
			let s1 = w[i- 2].rotate_right(17) ^ w[i- 2].rotate_right(19) ^ (w[i- 2] >> 10);
			w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
		}

		/*
	    Initialize working variables to current hash value:
		*/
		let [
			mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h
		] = self.hash;

		/*
	    Compression function main loop:
	    for i from 0 to 63
		*/
		for i in 0..64 {
			let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
			let ch = (e & f) ^ (!e & g);
			let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
			let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
			let maj = (a & b) ^ (a & c) ^ (b & c);
			let temp2 = s0.wrapping_add(maj);
			/*
	        S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
	        ch := (e and f) xor ((not e) and g)
	        temp1 := h + S1 + ch + k[i] + w[i]
	        S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
	        maj := (a and b) xor (a and c) xor (b and c)
	        temp2 := S0 + maj
			*/

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
	    self.hash[0] = self.hash[0].wrapping_add(a);
	    self.hash[1] = self.hash[1].wrapping_add(b);
	    self.hash[2] = self.hash[2].wrapping_add(c);
	    self.hash[3] = self.hash[3].wrapping_add(d);
	    self.hash[4] = self.hash[4].wrapping_add(e);
	    self.hash[5] = self.hash[5].wrapping_add(f);
	    self.hash[6] = self.hash[6].wrapping_add(g);
	    self.hash[7] = self.hash[7].wrapping_add(h);
	}

	pub fn digest(&self) -> [u8; 32] {
		let mut digest = [0; 32];

		for (c, h) in digest.chunks_exact_mut(4).zip(self.hash) {
			c.copy_from_slice(&h.to_be_bytes());
		}

		digest
	}
}

fn sha256(mut original_msg: Vec<u8>) -> [u8; 32] {
	/*
	Initialize hash values:
	(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	*/

	/*
	Pre-processing (Padding):
	begin with the original message of length L bits
	append a single '1' bit
	append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
	append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
	such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)
	*/

	let len = original_msg.len();

	original_msg.push(0x80);

	while (original_msg.len() + 8) % 64 != 0 {
		original_msg.push(0x00);
	}

	original_msg.extend_from_slice(&(len * 8).to_be_bytes());

	assert_eq!(original_msg.len() % 64, 0);

	/*
	Process the message in successive 512-bit chunks:
	break message into 512-bit chunks
	for each chunk
	*/
	let mut state = Sha256State::new();

	for chunk in original_msg.chunks_exact(64) {
		state.update(chunk.try_into().unwrap());
	}

	state.digest()

	/*
	Produce the final hash value (big-endian):
	digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7

	*/
}

#[cfg(test)]
mod test {
	use crate::util::parse_hex_32;

	use super::*;

	#[test]
	fn empty() {
		let digest = sha256(b"".into());
		assert_eq!(digest, parse_hex_32("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"));
	}

	#[test]
	fn abc() {
		let digest = sha256(b"abc".into());
		assert_eq!(digest, parse_hex_32("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"));
	}
}