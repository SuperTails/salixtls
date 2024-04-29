use std::net::{TcpStream, UdpSocket};

use hmac::Mac;
use x25519_dalek::PublicKey;

use crate::{hkdf::{HmacSha256, TranscriptHash}, premaster_secrets::PremasterSecret, secrets::{dump_premaster_secrets, EarlySecrets, EcdhKeypair, HandshakeSecrets, MasterSecrets}, stream::TlsRecordStream, wire::{CipherSuite, ClientHello, ContentType, Extension, Handshake, KeyShareEntry, NamedGroup, PacketReader, PlaintextError, ProtocolVersion, Random, TLSPlaintext}};

pub mod dns;
pub mod wire;
pub mod hkdf;
pub mod secrets;
pub mod premaster_secrets;
pub mod stream;

fn query_dns() {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect("8.8.8.8:53").unwrap();

    let mut query = Vec::new();

    query.extend_from_slice(&dns::MessageHeader::query(0x1234, 1).to_bytes());
    query.extend_from_slice(&dns::Question {
        name: "salix6502.lan.local.cmu.edu".into(),
        ty: 0x0001, // A
        class: 0x0001,
    }.to_bytes());
    
    sock.send(&query).unwrap();

    let mut response = [0; 256];
    let num_recv = sock.recv(&mut response).unwrap();
    let mut response = &response[..num_recv];

    let response_header = dns::MessageHeader::from_bytes(response[0..12].try_into().unwrap());
    response = &response[12..];
    println!("{:?}", response_header);

    for _ in 0..response_header.num_questions {
        let (question, tail) = dns::Question::from_bytes(response);
        response = tail;
        println!("{:?}", question);
    }

    for _ in 0..response_header.num_answer_rrs {
        let (answer, tail) = dns::ResourceRecord::from_bytes(response);
        response = tail;
        println!("{:?}", answer);
    }

    println!("{:?}", &response);

}

fn _premaster() {
    let pms = premaster_secrets::parse_premaster_secrets_file("./sample_capture/premaster_rust_lang_org2.txt");

    dbg!(pms.iter().filter(|s| matches!(s, PremasterSecret::HandshakeTraffic { .. })).count());

    let messages = [
        std::fs::read("./sample_capture/client_hello.bin").unwrap(),
        std::fs::read("./sample_capture/server_hello.bin").unwrap(),
    ];

    for s in pms {
        if let PremasterSecret::HandshakeTraffic { common, client, server } = s {
            let msgs = messages.iter().map(|m| m.as_slice()).collect::<Vec<_>>();
            let client_handshake_traffic_secret = hkdf::derive_secret(&common, b"c hs traffic", todo!());
            let server_handshake_traffic_secret = hkdf::derive_secret(&common, b"s hs traffic", todo!());

            if client_handshake_traffic_secret == client || server_handshake_traffic_secret == server {
                panic!();
            }

            println!("{:?}\n{:?}", client_handshake_traffic_secret, server_handshake_traffic_secret);
            println!("{:?}\n{:?}", client, server);
            println!();
        }
    }
}

pub struct TlsStream {
    host: String,
    record_stream: TlsRecordStream,
    client_random: Random,
    transcript_hash: TranscriptHash,
    rx_counter: u64,
    tx_counter: u64,
    master_secrets: MasterSecrets,
}

impl TlsStream {
    pub fn new(host: String) -> Self {
        let mut record_stream = TlsRecordStream::new(TcpStream::connect((&*host, 443)).unwrap());
        let client_random = Random::new_from_rng();
        let mut transcript_hash = TranscriptHash::new();
        let mut rx_counter = 0;
        let mut tx_counter = 0;
        /*let mut s = TlsStream {
            host: host.clone(),
            record_stream: TlsRecordStream::new(TcpStream::connect((host, 443)).unwrap()),
            client_random: Random::new_from_rng(),
            transcript_hash: TranscriptHash::new(),
            rx_counter: 0,
            tx_counter: 0,
        };*/

        /* ================ */
        /* Send ClientHello */
        /* ================ */

        let ecdh = EcdhKeypair::generate_sus();
        let client_hello = Handshake::ClientHello(ClientHello {
            random: client_random,
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                Extension::SupportedVersions {
                    versions: vec![ProtocolVersion(0x0304)]
                },
                Extension::ServerName {
                    host_names: vec![host.clone()],
                },
                Extension::SupportedGroups {
                    named_group_list: vec![NamedGroup::X25519],
                },
                Extension::KeyShare {
                    client_shares: vec![
                        KeyShareEntry {
                            group: NamedGroup::X25519,
                            key_exchange: ecdh.public.as_bytes().into(),
                        }
                    ]
                },
                Extension::Unknown {
                    extension_type: 13,
                    data: vec![0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1],
                }
            ]
        });

        let client_hello_bytes = client_hello.to_bytes();
        transcript_hash.add_message(&client_hello_bytes);

        let client_hello_record = TLSPlaintext {
            content_type: ContentType::Handshake,
            fragment: client_hello_bytes,
        };
        record_stream.send_record(&client_hello_record).unwrap();

        /* ==================== */
        /* Wait for ServerHello */
        /* ==================== */

        let early_secrets = EarlySecrets::generate(&[0; 32]);

        let record = record_stream.recv_record();

        let handshake_secrets = match record.content_type {
            ContentType::Invalid => panic!(),
            ContentType::ChangeCipherSpec => todo!(),
            ContentType::Alert => todo!(),
            ContentType::Handshake => {
                transcript_hash.add_message(&record.fragment);

                let mut r = PacketReader::new(record.fragment);
                let handshake = Handshake::from_bytes(&mut r).unwrap();
                assert!(r.finished());

                let Handshake::ServerHello(server_hello) = handshake else {
                    panic!("unexpected handshake message");
                };

                let mut shared = None;
                for ext in &server_hello.extensions {
                    if let Extension::KeyShare { client_shares } = ext {
                        shared = Some(&client_shares[0]);
                    }
                }
                let shared = shared.unwrap();
                let server_pk: [u8; 32] = shared.key_exchange[..].try_into().unwrap();

                let server_pubkey = PublicKey::from(server_pk);
                eprintln!("Server pubkey: {:?}", server_pubkey);
                
                let handshake = HandshakeSecrets::generate(&early_secrets, ecdh, &server_pubkey, &transcript_hash);
                println!("Handshake secret: {:?}", handshake.handshake_secret);

                dump_premaster_secrets("pms.txt", &host, &client_random, &handshake);

                handshake
            }
            ContentType::ApplicationData => panic!("unexpected ApplicationData"),
        };

        /* ================= */
        /* Rest of handshake */
        /* ================= */

        let mut r = PacketReader::new(Vec::new());

        let mut get_next_message = |r: &mut PacketReader, ts: &mut TranscriptHash| {
            if r.finished() {
                let record = loop {
                    let record = record_stream.recv_record();

                    match record.content_type {
                        ContentType::Invalid => todo!(),
                        ContentType::ChangeCipherSpec => {
                            println!("Ignoring ChangeCipherSpec");
                        },
                        ContentType::Alert => todo!(),
                        ContentType::Handshake => todo!(),
                        ContentType::ApplicationData => {
                            break record;
                        }
                    }
                };

                let plaintext = TLSPlaintext::decrypt(record.fragment, &handshake_secrets.server_write_key, rx_counter);
                rx_counter += 1;
                assert_eq!(plaintext.content_type, ContentType::Handshake);
                *r = PacketReader::new(plaintext.fragment);
            }

            let old_offset = r.offset;
            let hs = Handshake::from_bytes(r).unwrap();
            ts.add_message(&r.data[old_offset..r.offset]);

            hs
        };

        let enc_ext = get_next_message(&mut r, &mut transcript_hash);
        let Handshake::EncryptedExtensions(_enc_ext) = enc_ext else {
            panic!("unexpected handshake message");
        };

        let cert = get_next_message(&mut r, &mut transcript_hash);
        let Handshake::Certificate(_cert) = cert else {
            panic!("unexpected handshake message");
        };

        let cert_verif = get_next_message(&mut r, &mut transcript_hash);
        let Handshake::CertificateVerify(_cert_vertif) = cert_verif else {
            panic!("unexpected handshake message");
        };

        let ts = transcript_hash.compute();
        
        let finished = get_next_message(&mut r, &mut transcript_hash);
        let Handshake::Finished(hmac) = finished else {
            panic!("unexpected handshake message");
        };

        let finished_key: [u8; 32] = hkdf::expand_label(&handshake_secrets.server_handshake_traffic_secret, b"finished", b"", 32).try_into().unwrap();

    	let mut mac = <HmacSha256 as Mac>::new_from_slice(&finished_key).unwrap();
        mac.update(&ts);
        mac.verify(&hmac.into()).unwrap();

        let master_secrets = MasterSecrets::generate(&handshake_secrets, &transcript_hash);

        /* send Client Finished message */

        let finished_key: [u8; 32] = hkdf::expand_label(&handshake_secrets.client_handshake_traffic_secret, b"finished", b"", 32).try_into().unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&finished_key).unwrap();
        mac.update(&transcript_hash.compute());
        let mac: [u8; 32] = mac.finalize().into_bytes().into();
        let fragment = Handshake::Finished(mac).to_bytes();

        transcript_hash.add_message(&fragment);

        let encrypted = TLSPlaintext {
            content_type: ContentType::Handshake,
            fragment,
        }.encrypt(
            &handshake_secrets.client_write_key,
            tx_counter
        );

        let payload = TLSPlaintext {
            content_type: ContentType::ApplicationData,
            fragment: encrypted
        };

        println!("Sending finished message!");

        rx_counter = 0;
        tx_counter = 0;

        record_stream.send_record(&payload).unwrap();

        TlsStream {
            host,
            record_stream,
            client_random,
            transcript_hash,
            rx_counter,
            tx_counter,
            master_secrets,
        }
    }

    pub fn send(&mut self, data: &[u8]) {
        let data = TLSPlaintext {
            content_type: ContentType::ApplicationData,
            fragment: data.into(),
        }.encrypt(&self.master_secrets.client_write_key, self.tx_counter);
        self.tx_counter += 1;

        let payload = TLSPlaintext {
            content_type: ContentType::ApplicationData,
            fragment: data,
        };

        self.record_stream.send_record(&payload).unwrap();

    }

    pub fn recv(&mut self) -> Vec<u8> {
        loop {
            let record = self.record_stream.recv_record();
            assert_eq!(record.content_type, ContentType::ApplicationData);
            let record = TLSPlaintext::decrypt(record.fragment, &self.master_secrets.server_write_key, self.rx_counter);
            self.rx_counter += 1;
            self.transcript_hash.add_message(&record.fragment);

            match record.content_type {
                ContentType::Invalid => todo!(),
                ContentType::ChangeCipherSpec => todo!(),
                ContentType::Alert => todo!(),
                ContentType::Handshake => {
                    // TODO: Handle session ticket?
                }
                ContentType::ApplicationData => {
                    return record.fragment;
                }
            }
        }
    }
}

pub enum State {
    Start { ecdh: EcdhKeypair },
    WaitServerHello { ecdh: EcdhKeypair, early_secrets: EarlySecrets, },
    WaitHandshakeFinish { handshake_secrets: HandshakeSecrets },
    Connected { master_secrets: MasterSecrets },
}

fn main() {
    println!("Hello, world!");

    //let host = "www.rust-lang.org";
    let host = "www.google.com";
    //let host = "labeltron.roboclub.org";

    let mut stream = TlsStream::new(host.into());

    let data = format!("\
        GET / HTTP/1.1\r\n\
        Host: {}\r\n\
        User-Agent: SalixTLS\r\n\
        \r\n\
        \r\n\
        ", host);

    stream.send(data.as_bytes());

    println!("{:?}", String::from_utf8_lossy(&stream.recv()));
}
