#![allow(dead_code)]

pub fn parse_hex(mut s: &str) -> Vec<u8> {
	let mut result = Vec::new();
	while !s.is_empty() {
		s = s.trim();
		result.push(u8::from_str_radix(&s[..2], 16).unwrap());
		s = &s[2..];
	}
	result
}

pub fn parse_hex_32(s: &str) -> [u8; 32] {
	parse_hex(s).try_into().unwrap()
}
