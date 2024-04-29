use hmac::{digest::CtOutput, Hmac, Mac};
use sha2::{Sha256, Digest};

pub type HmacSha256 = Hmac<Sha256>;

type CtOutput256 = CtOutput<HmacSha256>;

pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
	let mut mac = HmacSha256::new_from_slice(salt).unwrap();
	mac.update(ikm);
	mac.finalize().into_bytes().into()
}

pub fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
	let n = len.div_ceil(32);
	assert!(n < 255);
	let n = n as u8;

	let mut result = Vec::<u8>::new();

	let mut t = vec![];

	for i in 0..n {
		let mut mac = HmacSha256::new_from_slice(prk).unwrap();
		mac.update(&t);
		mac.update(info);
		let c = i + 1;
		mac.update(std::slice::from_ref(&c));
		t = mac.finalize().into_bytes().to_vec();
		result.extend_from_slice(&t);
	}

	result.truncate(len);
	result
}

pub fn expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
	let mut hkdf_label = Vec::new();
	hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
	hkdf_label.push((6 + label.len()).try_into().unwrap());
	hkdf_label.extend_from_slice(b"tls13 ");
	hkdf_label.extend_from_slice(label);
	hkdf_label.push(context.len().try_into().unwrap());
	hkdf_label.extend_from_slice(context);

	expand(secret, &hkdf_label, length)
}

pub fn derive_secret(secret: &[u8; 32], label: &[u8], messages: &TranscriptHash) -> [u8; 32] {
	expand_label(secret, label, &messages.compute(), 32).try_into().unwrap()
}

#[derive(Default, Clone)]
pub struct TranscriptHash {
	hash: Sha256,
}

impl TranscriptHash {
	pub fn new() -> Self {
		Default::default()
	}

	pub fn add_message(&mut self, data: &[u8]) {
		self.hash.update(data);
	}

	pub fn compute(&self) -> [u8; 32] {
		self.hash.clone().finalize().into()
	}
}



#[cfg(test)]
mod test {
	use super::*;

	#[test]
	pub fn rfc5869_test_case_1() {
		let ikm = [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
		let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
		let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];

		let l = 42;

		let prk = extract(&salt, &ikm);

		assert_eq!(
			prk,
			[7, 119, 9, 54, 44, 46, 50, 223, 13, 220, 63, 13, 196, 123, 186, 99, 144, 182, 199, 59, 181, 15, 156, 49, 34, 236, 132, 74, 215, 194, 179, 229]
		);

		let okm = expand(&prk, &info, l);

		assert_eq!(
			okm,
			[60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10, 144, 207, 26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191, 52, 0, 114, 8, 213, 184, 135, 24, 88, 101]
		);
	}
}