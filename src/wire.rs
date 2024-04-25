use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, KeyInit};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::secrets::WriteKey;

pub struct PacketReader {
	pub data: Vec<u8>,
	pub offset: usize,
}

impl PacketReader {
	pub fn new(data: Vec<u8>) -> Self {
		PacketReader {
			data,
			offset: 0,
		}
	}

	pub fn read_u8(&mut self) -> u8 {
		let b = self.data[self.offset];
		self.offset += 1;
		b
	}

	pub fn read_u16(&mut self) -> u16 {
		u16::from_be_bytes([self.read_u8(), self.read_u8()])
	}

	pub fn read_u24(&mut self) -> u32 {
		u32::from_be_bytes([0, self.read_u8(), self.read_u8(), self.read_u8()])
	}

	pub fn read_slice(&mut self, len: usize) -> &[u8] {
		assert!(len <= self.remaining());
		let slice = &self.data[self.offset..][..len];
		self.offset += len;
		slice
	}

	pub fn finished(&self) -> bool {
		self.offset == self.data.len()
	}

	pub fn remaining(&self) -> usize {
		self.data.len() - self.offset
	}
}

#[derive(Default)]
pub struct PacketBuilder(Vec<u8>);

impl PacketBuilder {
	pub fn new() -> Self {
		Default::default()
	}

	pub fn push_u8(&mut self, value: u8) {
		self.0.push(value);
	}

	pub fn push_u16(&mut self, value: u16) {
		self.0.extend_from_slice(&value.to_be_bytes());
	}

	pub fn push_u24(&mut self, value: u32) {
		let v = value.to_be_bytes();
		assert_eq!(v[0], 0);
		self.0.extend_from_slice(&v[1..]);
	}

	pub fn extend_from_slice(&mut self, bytes: &[u8]) {
		self.0.extend_from_slice(bytes);
	}

	pub fn extend_length_prefixed(&mut self, bytes: &[u8], max_len: usize) {
		let first_nonzero = max_len.to_be_bytes().into_iter().enumerate().find(|(_i, b)| *b != 0).unwrap().0;

		self.extend_from_slice(&bytes.len().to_be_bytes()[first_nonzero..]);
		self.extend_from_slice(bytes);
	}
}

/*
uint16 ProtocolVersion;
opaque Random[32];

uint8 CipherSuite[2];    /* Cryptographic suite selector */

*/

#[derive(Debug)]
pub struct ProtocolVersion(pub u16);

#[derive(Debug)]
pub struct Random(pub [u8; 32]);

impl Random {
	pub fn new_from_rng() -> Self {
		let mut bytes = [0; 32];
		let mut rng = StdRng::from_entropy();
		rng.fill_bytes(&mut bytes);
		Random(bytes)
	}

	pub fn from_bytes(b: &mut PacketReader) -> Self {
		Random(b.read_slice(32).try_into().unwrap())
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureScheme(u16);

impl SignatureScheme {
	pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
}

#[derive(Debug, Clone, Copy)]
pub struct CipherSuite(u16);

impl CipherSuite {
	pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite(0x13_01);
}

#[derive(Debug)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
	pub const X25519: NamedGroup = NamedGroup(0x001D);

	pub const FFDHE2048: NamedGroup = NamedGroup(0x0100);

	pub fn to_bytes(&self) -> [u8; 2] {
		self.0.to_be_bytes()
	}
}

/*
struct {
	ExtensionType extension_type;
	opaque extension_data<0..2^16-1>;
} Extension;

enum {
	server_name(0),                             /* RFC 6066 */
	max_fragment_length(1),                     /* RFC 6066 */
	status_request(5),                          /* RFC 6066 */
	supported_groups(10),                       /* RFC 8422, 7919 */
	signature_algorithms(13),                   /* RFC 8446 */
	use_srtp(14),                               /* RFC 5764 */
	heartbeat(15),                              /* RFC 6520 */
	application_layer_protocol_negotiation(16), /* RFC 7301 */
	signed_certificate_timestamp(18),           /* RFC 6962 */
	client_certificate_type(19),                /* RFC 7250 */
	server_certificate_type(20),                /* RFC 7250 */
	padding(21),                                /* RFC 7685 */
	pre_shared_key(41),                         /* RFC 8446 */
	early_data(42),                             /* RFC 8446 */
	supported_versions(43),                     /* RFC 8446 */
	cookie(44),                                 /* RFC 8446 */
	psk_key_exchange_modes(45),                 /* RFC 8446 */
	certificate_authorities(47),                /* RFC 8446 */
	oid_filters(48),                            /* RFC 8446 */
	post_handshake_auth(49),                    /* RFC 8446 */
	signature_algorithms_cert(50),              /* RFC 8446 */
	key_share(51),                              /* RFC 8446 */
	(65535)
} ExtensionType;
*/

/*
struct {
	NamedGroup group;
	opaque key_exchange<1..2^16-1>;
} KeyShareEntry;
*/

#[derive(Debug)]
pub struct KeyShareEntry {
	pub group: NamedGroup,
	pub key_exchange: Vec<u8> 
}

impl KeyShareEntry {
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut payload = PacketBuilder::new();
		payload.extend_from_slice(&self.group.to_bytes());
		payload.push_u16(self.key_exchange.len().try_into().unwrap());
		payload.extend_from_slice(&self.key_exchange);
		payload.0
	}

	pub fn from_bytes(r: &mut PacketReader) -> Result<KeyShareEntry, DecodeError> {
		let group = NamedGroup(r.read_u16());
		let len = r.read_u16() as usize;
		let key_exchange = r.read_slice(len).to_owned();
		Ok(KeyShareEntry { group, key_exchange })
	}
}

#[derive(Debug)]
pub enum Extension {
	/*
	struct {
		NameType name_type;
		select (name_type) {
			case host_name: HostName;
		} name;
	} ServerName;

	enum {
		host_name(0), (255)
	} NameType;

	opaque HostName<1..2^16-1>;

	struct {
		ServerName server_name_list<1..2^16-1>
	} ServerNameList;
	*/
	ServerName { host_names: Vec<String> },
	/*
	struct {
		NamedGroup named_group_list<2..2^16-1>;
	} NamedGroupList;
	*/
	SupportedGroups { named_group_list: Vec<NamedGroup> },
	/*
	struct {
		select (Handshake.msg_type) {
			case client_hello:
				 ProtocolVersion versions<2..254>;

			case server_hello: /* and HelloRetryRequest */
				 ProtocolVersion selected_version;
		};
	} SupportedVersions;
	*/
	SupportedVersions { versions: Vec<ProtocolVersion> },
	/*
	struct {
		KeyShareEntry client_shares<0..2^16-1>;
	} KeyShareClientHello;
	 */
	KeyShare { client_shares: Vec<KeyShareEntry> },

	Unknown { extension_type: u16, data: Vec<u8> },
}

impl Extension {
	pub fn extension_type(&self) -> u16 {
		match self {
			Extension::ServerName { .. } => 0,
			Extension::SupportedGroups { .. } => 10,
			Extension::SupportedVersions { .. } => 43,
			Extension::KeyShare { .. } => 51,
			Extension::Unknown { extension_type, .. } => *extension_type,
		}
	}

	pub fn to_bytes(&self, client: bool) -> Vec<u8> {
		let mut payload = PacketBuilder::new();
		match self {
			Extension::ServerName { host_names } => {
				let mut list = PacketBuilder::new();
				for name in host_names {
					list.push_u8(0);
					list.push_u16(name.len().try_into().unwrap());
					list.extend_from_slice(name.as_bytes());
				}
				payload.push_u16(list.0.len().try_into().unwrap());
				payload.0.extend_from_slice(&list.0);
			}
			Extension::SupportedGroups { named_group_list } => {
				payload.push_u16((named_group_list.len() * 2).try_into().unwrap());
				for named_group in named_group_list {
					payload.push_u16(named_group.0);
				}
			}
			Extension::SupportedVersions { versions } => {
				if client {
					payload.push_u8((versions.len() * 2).try_into().unwrap());
					for v in versions {
						payload.push_u16(v.0);
					}
				}
			}
			Extension::KeyShare { client_shares } => {
				let mut list = PacketBuilder::new();
				for entry in client_shares {
					list.extend_from_slice(&entry.to_bytes());
				}
				payload.push_u16(list.0.len().try_into().unwrap());
				payload.0.extend_from_slice(&list.0);
			}
			Extension::Unknown { data, .. } => {
				payload.extend_from_slice(data);
			}
		}

		let mut b = PacketBuilder::new();
		b.push_u16(self.extension_type());
		b.push_u16(payload.0.len().try_into().unwrap());
		b.extend_from_slice(&payload.0);
		b.0
	}

	pub fn from_bytes(b: &mut PacketReader, client: bool) -> Result<Self, DecodeError> {
		let extension_type = b.read_u16();
		let len = b.read_u16() as usize;
		let data = b.read_slice(len).to_owned();

		match extension_type {
			51 => {
				let mut r = PacketReader::new(data);
				let entry = KeyShareEntry::from_bytes(&mut r)?;
				assert!(r.finished());
				Ok(Extension::KeyShare { client_shares: vec![entry] })
			}
			_ => Ok(Extension::Unknown { extension_type, data }),
		}
	}
}


/*
struct {
	ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	Random random;
	opaque legacy_session_id<0..32>;
	CipherSuite cipher_suites<2..2^16-2>;
	opaque legacy_compression_methods<1..2^8-1>;
	Extension extensions<8..2^16-1>;
} ClientHello;
*/
#[derive(Debug)]
pub struct ClientHello {
	pub random: Random,
	//legacy_session_id: Vec<u8>,
	pub cipher_suites: Vec<CipherSuite>,
	//legacy_compression_methods: Vec<u8>,
	pub extensions: Vec<Extension>
}

impl ClientHello {
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut b = PacketBuilder::new();
		b.push_u16(0x0303); // Legacy version
		b.extend_from_slice(&self.random.0);
		b.push_u8(0); // legacy session ID of size 0

		b.push_u16((self.cipher_suites.len() * 2).try_into().unwrap());
		for cs in &self.cipher_suites {
			b.extend_from_slice(&cs.0.to_be_bytes());
		}

		b.push_u8(1); // legacy compression methods
		b.push_u8(0); // (null)

		let mut extensions = PacketBuilder::new();
		for ext in &self.extensions {
			extensions.extend_from_slice(&ext.to_bytes(true));
		}
		b.push_u16(extensions.0.len().try_into().unwrap());
		b.extend_from_slice(&extensions.0);

		b.0
	}
}

/*
struct {
	ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	Random random;
	opaque legacy_session_id_echo<0..32>;
	CipherSuite cipher_suite;
	uint8 legacy_compression_method = 0;
	Extension extensions<6..2^16-1>;
} ServerHello;
*/

#[derive(Debug)]
pub struct ServerHello {
	pub random: Random,
	pub legacy_session_id_echo: Vec<u8>,
	pub cipher_suite: CipherSuite,
	// uint8_t legacy_compression_method = 0
	pub extensions: Vec<Extension>,
}

impl ServerHello {
	pub fn from_bytes(b: &mut PacketReader) -> Result<Self, DecodeError> {
		let legacy_version = b.read_u16();
		if legacy_version != 0x0303 {
			return Err(format!("unsupported legacy version {:#06X}", legacy_version));
		}
		let random = Random::from_bytes(b);
		let len = b.read_u8() as usize;
		let legacy_session_id_echo = b.read_slice(len).to_owned();
		let cipher_suite = CipherSuite(b.read_u16());
		let legacy_compression_method = b.read_u8();
		if legacy_compression_method != 0 {
			return Err(format!("unsupported legacy compression method {legacy_compression_method}"));
		}
		let len = b.read_u16() as usize;
		let end = b.offset + len;
		let mut extensions = Vec::new();
		while b.offset < end {
			extensions.push(Extension::from_bytes(b, false)?);
		}
		Ok(ServerHello { random, legacy_session_id_echo, cipher_suite, extensions })
	}
}

/*

      enum {
          X509(0),
          RawPublicKey(2),
          (255)
      } CertificateType;

      struct {
          select (certificate_type) {
              case RawPublicKey:
                /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

              case X509:
                opaque cert_data<1..2^24-1>;
          };
          Extension extensions<0..2^16-1>;
      } CertificateEntry;
*/
/*
pub struct CertificateEntry {

}
*/

/*
      struct {
          opaque certificate_request_context<0..2^8-1>;
          CertificateEntry certificate_list<0..2^24-1>;
      } Certificate;

*/
#[derive(Debug)]
pub struct Certificate {
	certificate_request_context: Vec<u8>,
	certificate_list: Vec<u8>,
}

impl Certificate {
	pub fn from_bytes(r: &mut PacketReader) -> Result<Self, DecodeError> {
		let len = r.read_u8() as usize;
		let certificate_request_context = r.read_slice(len).to_owned();
		let len = r.read_u24() as usize;
		let end = r.offset + len;
		// TODO:
		let certificate_list = r.read_slice(len).to_owned();
		/*let mut certificate_list = Vec::new();
		while r.offset < len {
			certificate_list.push(CertificateEntry::from_bytes(r)?);
		}*/
		Ok(Certificate {
			certificate_request_context,
			certificate_list,
		})
	}
}

/*
      enum {
          client_hello(1),
          server_hello(2),
          new_session_ticket(4),
          end_of_early_data(5),
          encrypted_extensions(8),
          certificate(11),
          certificate_request(13),
          certificate_verify(15),
          finished(20),
          key_update(24),
          message_hash(254),
          (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;    /* handshake type */
          uint24 length;             /* remaining bytes in message */
          select (Handshake.msg_type) {
              case client_hello:          ClientHello;
              case server_hello:          ServerHello;
              case end_of_early_data:     EndOfEarlyData;
              case encrypted_extensions:  EncryptedExtensions;
              case certificate_request:   CertificateRequest;
              case certificate:           Certificate;
              case certificate_verify:    CertificateVerify;
              case finished:              Finished;
              case new_session_ticket:    NewSessionTicket;
              case key_update:            KeyUpdate;
          };
      } Handshake;
*/
#[derive(Debug)]
pub enum Handshake {
	ClientHello(ClientHello),
	ServerHello(ServerHello),
	EncryptedExtensions(Vec<Extension>),
	Certificate(Certificate),
	CertificateVerify(Vec<u8>),
	Finished([u8; 32]),
}

impl Handshake {
	pub fn handshake_type(&self) -> u8 {
		match self {
			Handshake::ClientHello(_) => 1,
			Handshake::ServerHello(_) => 2,
			Handshake::EncryptedExtensions(_) => 8,
			Handshake::Certificate(_) => 11,
			Handshake::CertificateVerify(_) => 15,
			Handshake::Finished(_) => 20,
		}
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let payload = match self {
			Handshake::ClientHello(ch) => ch.to_bytes(),
			Handshake::ServerHello(_) => todo!(),
			Handshake::EncryptedExtensions(_) => todo!(),
			Handshake::Certificate(_) => todo!(),
			Handshake::CertificateVerify(_) => todo!(),
			Handshake::Finished(hmac) => hmac.into(),
		};

		let mut b = PacketBuilder::new();
		b.push_u8(self.handshake_type());
		b.push_u24(payload.len().try_into().unwrap());
		b.extend_from_slice(&payload);
		b.0
	}

	pub fn from_bytes(r: &mut PacketReader) -> Result<Self, DecodeError> {
		let handshake_type = r.read_u8();
		let len = r.read_u24() as usize;
		let end = r.offset + len;
		match handshake_type {
			1 => unimplemented!("parse ClientHello"),
			2 => {
				let server_hello = ServerHello::from_bytes(r)?;
				assert_eq!(r.offset, end);
				Ok(Handshake::ServerHello(server_hello))
			}
			8 => {
				let ext_len = r.read_u16() as usize;
				assert_eq!(end, r.offset + ext_len);
				let mut extensions = Vec::new();
				while r.offset < end {
					extensions.push(Extension::from_bytes(r, false)?);
				}
				assert_eq!(r.offset, end);
				Ok(Handshake::EncryptedExtensions(extensions))
			}
			11 => {
				let cert = Certificate::from_bytes(r)?;
				assert_eq!(r.offset, end);
				Ok(Handshake::Certificate(cert))
			}
			15 => {
				Ok(Handshake::CertificateVerify(r.read_slice(len).to_owned()))
			}
			20 => {
				Ok(Handshake::Finished(r.read_slice(len).try_into().unwrap()))
			}
			_ => todo!("{}", handshake_type),
		}
	}
}


// Record layer

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
	Invalid = 0,
	ChangeCipherSpec = 20,
	Alert = 21,
	Handshake = 22,
	ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
	type Error = u8;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(ContentType::Invalid),
			20 => Ok(ContentType::ChangeCipherSpec),
			21 => Ok(ContentType::Alert),
			22 => Ok(ContentType::Handshake),
			23 => Ok(ContentType::ApplicationData),
			_ => Err(value),
		}
	}
}

/*

enum {
	invalid(0),
	change_cipher_spec(20),
	alert(21),
	handshake(22),
	application_data(23),
	(255)
} ContentType;

struct {
	ContentType type;
	ProtocolVersion legacy_record_version;
	uint16 length;
	opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
*/

type DecodeError = String;

#[derive(Debug)]
pub enum PlaintextError {
	Other(String),
	NotEnoughData(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub struct TLSPlaintext {
	pub content_type: ContentType,
	//legacy_record_version: ProtocolVersion,
	pub fragment: Vec<u8>,
}

impl TLSPlaintext {
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut b = PacketBuilder::new();
		b.push_u8(self.content_type as u8);
		b.push_u16(0x0303); // legacy_record_version
		b.push_u16(self.fragment.len().try_into().unwrap());
		b.extend_from_slice(&self.fragment);
		b.0
	}

	pub fn from_bytes(p: &mut PacketReader) -> Result<Self, PlaintextError> {
		let old_offset = p.offset;

		let content_type = match ContentType::try_from(p.read_u8()) {
			Ok(ct) => ct,
			Err(err) => {
				p.offset = old_offset;
				return Err(PlaintextError::Other(format!("unknown content type {err}")));
			}
		};

		let legacy_record_version = p.read_u16();
		if legacy_record_version != 0x0303 {
			p.offset = old_offset;
			return Err(PlaintextError::Other(format!("unknown legacy_record_version {legacy_record_version:#06X}")));
		}

		let len = p.read_u16() as usize;
		if len > p.data.len() - p.offset {
			let missing = len - (p.data.len() - p.offset);
			p.offset = old_offset;
			return Err(PlaintextError::NotEnoughData(missing));
		}

		let fragment = p.read_slice(len).to_owned();
		Ok(TLSPlaintext { content_type, fragment })
	}

	pub fn decrypt(mut data: Vec<u8>, key: &WriteKey, sequence_number: u64) -> Self {
	    let mut aes = Aes128Gcm::new(&(key.key.into()));

	    let mut additional_data = vec![];
	    additional_data.push(23); // ApplicationData
	    additional_data.push(0x03); additional_data.push(0x03); // legacy_record_version
	    additional_data.extend_from_slice(&(data.len() as u16).to_be_bytes());

	    let mut nonce = [0; 12];
	    nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());

	    for (n, iv) in nonce.iter_mut().zip(key.iv) {
	        *n ^= iv;
	    }
	    
	    aes.decrypt_in_place(
	        &nonce.into(),
	        &additional_data,
	        &mut data
	    ).unwrap();
	    
	    while data.ends_with(&[0]) {
	        data.pop();
	    }

		let content_type = ContentType::try_from(data.pop().unwrap()).unwrap();

		Self {
			content_type,
			fragment: data,
		}
	}

	pub fn encrypt(&self, key: &WriteKey, sequence_number: u64) -> Vec<u8> {
		let mut data = Vec::new();
		data.extend_from_slice(&self.fragment);
		data.push(self.content_type as u8);

	    let mut aes = Aes128Gcm::new(&(key.key.into()));

	    let mut additional_data = vec![];
	    additional_data.push(23); // ApplicationData
	    additional_data.push(0x03); additional_data.push(0x03); // legacy_record_version
	    additional_data.extend_from_slice(&(data.len() as u16 + 16).to_be_bytes());

	    let mut nonce = [0; 12];
	    nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());

	    for (n, iv) in nonce.iter_mut().zip(key.iv) {
	        *n ^= iv;
	    }

		aes.encrypt_in_place(
			&nonce.into(),
			&additional_data,
			&mut data
		).unwrap();

		data
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn roundtrip_protect() {
		let key = WriteKey {
			key: [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
			iv: [0xB, 0xA, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0],
		};
		let sequence_number = 42;

		let original = TLSPlaintext {
			content_type: ContentType::ApplicationData,
			fragment: b"Hello, world!".into(),
		};
		
		let encrypted = original.encrypt(&key, sequence_number);

		assert_eq!(encrypted.len(), original.fragment.len() + 16 + 1);

		let roundtripped = TLSPlaintext::decrypt(encrypted, &key, sequence_number);

		assert_eq!(original, roundtripped);
	}
}