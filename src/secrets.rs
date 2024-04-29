use std::io::Write;

use rand::{rngs::StdRng, SeedableRng};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{hkdf::{self, TranscriptHash}, wire::Random};

pub struct EcdhKeypair {
	pub private: EphemeralSecret,
	pub public: PublicKey,
}

impl EcdhKeypair {
	pub fn generate() -> Self {
		let private = EphemeralSecret::random_from_rng(StdRng::from_entropy());
		let public = PublicKey::from(&private);
		EcdhKeypair { private, public }
	}

	pub fn generate_sus() -> Self {
		let mut sus = [0_u8; 32];
		sus[0] = 1;
		let private = unsafe { std::mem::transmute::<_, EphemeralSecret>(sus) };
		let public = PublicKey::from(&private);
		EcdhKeypair { private, public }
	}
}

pub struct WriteKey {
	pub key: [u8; 16],
	pub iv:  [u8; 12],
}

impl WriteKey {
	pub fn generate(secret: &[u8; 32]) -> Self {
		let key: [u8; 16] = hkdf::expand_label(secret, b"key", b"", 16).try_into().unwrap();
		let iv:  [u8; 12] = hkdf::expand_label(secret, b"iv", b"", 12).try_into().unwrap();
		WriteKey { key, iv }
	}
}

pub struct EarlySecrets {
	pub early_secret: [u8; 32],
}

impl EarlySecrets {
	pub fn generate(psk: &[u8; 32]) -> Self {
		let early_secret = hkdf::extract(&[0; 32], psk);
		EarlySecrets { early_secret }
	}
}

pub struct HandshakeSecrets {
	pub handshake_secret: [u8; 32],

	pub client_handshake_traffic_secret: [u8; 32],
	pub server_handshake_traffic_secret: [u8; 32],

	pub client_write_key: WriteKey,
	pub server_write_key: WriteKey,
}

impl HandshakeSecrets {
	pub fn generate(early: &EarlySecrets, ecdh: EcdhKeypair, server_pubkey: &PublicKey, transcript: &TranscriptHash) -> Self {
		println!("PRIVATE KEY: {:?}", unsafe { std::mem::transmute::<_, &[u8; 32]>(&ecdh.private) });
		println!("SERVER PUBKEY {:?}", server_pubkey);
		let shared_secret = ecdh.private.diffie_hellman(server_pubkey);
		println!("SHARED SECRET {:?}", shared_secret.as_bytes());

		let early_derived = hkdf::derive_secret(&early.early_secret, b"derived", &TranscriptHash::default());
		let handshake_secret = hkdf::extract(&early_derived, shared_secret.as_bytes());

		println!("Handshake secret: {:?}", handshake_secret);

		let client_handshake_traffic_secret = hkdf::derive_secret(&handshake_secret, b"c hs traffic", transcript);
		let server_handshake_traffic_secret = hkdf::derive_secret(&handshake_secret, b"s hs traffic", transcript);

		let server_write_key = WriteKey::generate(&server_handshake_traffic_secret);
		let client_write_key = WriteKey::generate(&client_handshake_traffic_secret);

		HandshakeSecrets {
			handshake_secret,
			client_handshake_traffic_secret,
			server_handshake_traffic_secret,
			server_write_key,
			client_write_key,
		}
	}
}

pub struct MasterSecrets {
	pub master_secret: [u8; 32],

	pub client_application_traffic_secret_0: [u8; 32],
	pub server_application_traffic_secret_0: [u8; 32],

	pub client_write_key: WriteKey,
	pub server_write_key: WriteKey,
}

impl MasterSecrets {
	pub fn generate(handshake: &HandshakeSecrets, transcript: &TranscriptHash) -> Self {
		let handshake_derived = hkdf::derive_secret(&handshake.handshake_secret, b"derived", &TranscriptHash::default());
		let ikm = [0; 32];
		let master_secret = hkdf::extract(&handshake_derived, &ikm);

		let client_application_traffic_secret_0 = hkdf::derive_secret(&master_secret, b"c ap traffic", transcript);
		let server_application_traffic_secret_0 = hkdf::derive_secret(&master_secret, b"s ap traffic", transcript);

		let server_write_key = WriteKey::generate(&server_application_traffic_secret_0);
		let client_write_key = WriteKey::generate(&client_application_traffic_secret_0);

		MasterSecrets {
		    master_secret,
		    client_application_traffic_secret_0,
		    server_application_traffic_secret_0,
			server_write_key,
			client_write_key,
		}
	}
}

struct HexDump<'a>(&'a [u8]);

impl std::fmt::Display for HexDump<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		for b in self.0 {
			write!(f, "{:02x}", b)?;
		}
		Ok(())
	}
}

pub fn dump_premaster_secrets(path: &str, host: &str, client_random: &Random, handshake: &HandshakeSecrets) {
	let mut f = std::fs::File::create(path).unwrap();

	let comment = format!("# SalixTLS request to host `{host}`\n");
	
	f.write_all(comment.as_bytes()).unwrap();

	let chts = format!(
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
		HexDump(&client_random.0),
		HexDump(&handshake.client_handshake_traffic_secret),
	);

	f.write_all(chts.as_bytes()).unwrap();

	let shts = format!(
		"SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
		HexDump(&client_random.0),
		HexDump(&handshake.server_handshake_traffic_secret),
	);

	f.write_all(shts.as_bytes()).unwrap();
}

#[cfg(test)]
mod test {
	use crate::wire::{Handshake, PacketReader};

	use super::*;

	fn parse_hex(mut s: &str) -> Vec<u8> {
		let mut result = Vec::new();
		while !s.is_empty() {
			s = s.trim();
			result.push(u8::from_str_radix(&s[..2], 16).unwrap());
			s = &s[2..];
		}
		result
	}

	fn parse_hex_32(s: &str) -> [u8; 32] {
		parse_hex(s).try_into().unwrap()
	}

	#[test]
	fn rfc8448_simple_1_rtt_handshake() {
		let mut messages = TranscriptHash::new();

		/* {client}  create an ephemeral x25519 key pair: */

		let private = parse_hex_32(
		 "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca
		  a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05"
		);
		// SAFETY: it's not.
		let private = unsafe { std::mem::transmute::<_, EphemeralSecret>(private) };

		let public = PublicKey::from(parse_hex_32(
		   "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe
			b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c"
		));

		assert_eq!(public, PublicKey::from(&private));

		let ecdh = EcdhKeypair {
			private,
			public
		};

		/* {client}  send handshake record: */

		let client_hello = parse_hex("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba
		1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02
		4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
		09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
		00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00
		00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d
		8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af
		2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
		03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
		02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

		messages.add_message(&client_hello);

		/* {server}  extract secret "early": */

		let psk = [0; 32];

		let early_secret = parse_hex_32(
		   "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
			10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"
		);

		let early_secrets = EarlySecrets::generate(&psk);

		assert_eq!(early_secret, early_secrets.early_secret);

		/* {server}  construct a ServerHello handshake message: */

		let server_hello = {
			let b = parse_hex("02 00 00 56 03 03 a6 af 06 a4 12 18 60
			dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
			d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
			76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
			dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");
			messages.add_message(&b);
			let mut parser = PacketReader::new(b);
			Handshake::from_bytes(&mut parser).unwrap()
		};

		let Handshake::ServerHello(server_hello) = server_hello else { unreachable!() };

		println!("{:?}", server_hello);

		let server_pubkey = PublicKey::from(parse_hex_32(
		   "c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1
		    56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"
		));

		/* {server}  derive secret for handshake "tls13 derived": */
		/* {server}  extract secret "handshake": */

		let handshake_secrets = HandshakeSecrets::generate(&early_secrets, ecdh, &server_pubkey, &messages);

		let handshake_secret = parse_hex_32(
		   "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
		    04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"
		);

		assert_eq!(handshake_secrets.handshake_secret, handshake_secret);

		/* {server}  derive secret "tls13 c hs traffic": */

		let tls13_c_hs_traffic = parse_hex_32(
		   "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
		    3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"
		);

		assert_eq!(handshake_secrets.client_handshake_traffic_secret, tls13_c_hs_traffic);

		/* {server}  derive secret "tls13 s hs traffic": */

		let tls13_s_hs_traffic = parse_hex_32(
		   "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
		    e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
		);

		assert_eq!(handshake_secrets.server_handshake_traffic_secret, tls13_s_hs_traffic);

		/* {server}  construct a Certificate handshake message: */

		let extensions = parse_hex("08 00 00 24 00 22 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
         00 02 40 01 00 00 00 00");

		messages.add_message(&extensions);

		let certificate = parse_hex("0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
         01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
         86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
         72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
         0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
         03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
         0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
         82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
         d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
		 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
         4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
         80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
         ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
         01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
         03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
         01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
         72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
         e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
         51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
         c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
         1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
         96 12 29 ac 91 87 b4 2b 4d e1 00 00"
		);

		messages.add_message(&certificate);

		let certificate_verify = parse_hex("0f 00 00 84 08 04 00 80 5a 74 7c
		5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
		b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
		86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
		be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
		5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
		3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3"
		);

		messages.add_message(&certificate_verify);

		let finished = parse_hex("14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
		dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
		18");

		messages.add_message(&finished);

		let master_secret = parse_hex_32("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
		47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19");

		let master_secrets = MasterSecrets::generate(&handshake_secrets, &messages);

		assert_eq!(master_secrets.master_secret, master_secret);

		let tls13_c_ap_traffic = parse_hex_32("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce
		65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");

		assert_eq!(master_secrets.client_application_traffic_secret_0, tls13_c_ap_traffic);

	}
}