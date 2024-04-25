pub enum PremasterSecret {
	HandshakeTraffic {
		common: [u8; 32],
		client: [u8; 32],
		server: [u8; 32],
	},
	TrafficSecret0 {
		common: [u8; 32],
		client: [u8; 32],
		server: [u8; 32],
	},
	Random {
		lhs: [u8; 32],
		rhs: [u8; 48],
	},
	Exporter {
		lhs: [u8; 32],
		rhs: [u8; 32],
	}
}

fn parse_hex_any(s: &str) -> Vec<u8> {
	assert_eq!(s.len() % 2, 0);

	(0..(s.len() / 2))
		.map(|i| u8::from_str_radix(&s[i * 2..][..2], 16).unwrap())
		.collect()
}

fn parse_hex_32(s: &str) -> [u8; 32] {
	assert_eq!(s.len(), 64);
	parse_hex_any(s).try_into().unwrap()
}

fn parse_hex_48(s: &str) -> [u8; 48] {
	assert_eq!(s.len(), 96);
	parse_hex_any(s).try_into().unwrap()
}

pub fn parse_premaster_secrets_file(path: &str) -> Vec<PremasterSecret> {
	let mut secrets = Vec::new();

	let file = std::fs::read_to_string(path).unwrap();
	let mut lines = file.lines();
	while let Some(line) = lines.next() {
		if line.starts_with('#') {
			// Comment
			continue;
		}
		
		if let Some(client_rest) = line.strip_prefix("CLIENT_HANDSHAKE_TRAFFIC_SECRET ") {
			let server_rest = lines.next().unwrap().strip_prefix("SERVER_HANDSHAKE_TRAFFIC_SECRET ").unwrap();

			let (c_common, client) = client_rest.split_once(' ').unwrap();
			let (s_common, server) = server_rest.split_once(' ').unwrap();

			let c_common = parse_hex_32(c_common);
			let s_common = parse_hex_32(s_common);
			assert_eq!(c_common, s_common);

			let client = parse_hex_32(client);
			let server = parse_hex_32(server);

			secrets.push(PremasterSecret::HandshakeTraffic { common: c_common, client, server })
		} else if let Some(client_rest) = line.strip_prefix("CLIENT_TRAFFIC_SECRET_0 ") {
			let server_rest = lines.next().unwrap().strip_prefix("SERVER_TRAFFIC_SECRET_0 ").unwrap();

			let (c_common, client) = client_rest.split_once(' ').unwrap();
			let (s_common, server) = server_rest.split_once(' ').unwrap();

			let c_common = parse_hex_32(c_common);
			let s_common = parse_hex_32(s_common);
			assert_eq!(c_common, s_common);

			let client = parse_hex_32(client);
			let server = parse_hex_32(server);

			secrets.push(PremasterSecret::TrafficSecret0 { common: c_common, client, server })
		} else if let Some(random) = line.strip_prefix("CLIENT_RANDOM ") {
			let (lhs, rhs) = random.split_once(' ').unwrap();
			let lhs = parse_hex_32(lhs);
			let rhs = parse_hex_48(rhs);
			secrets.push(PremasterSecret::Random { lhs, rhs });
		} else if let Some(rest) = line.strip_prefix("EXPORTER_SECRET ") {
			let (lhs, rhs) = rest.split_once(' ').unwrap();
			let lhs = parse_hex_32(lhs);
			let rhs = parse_hex_32(rhs);
			secrets.push(PremasterSecret::Exporter { lhs, rhs });
		} else {
			todo!("{:?}", line);
		}
	}

	secrets
}