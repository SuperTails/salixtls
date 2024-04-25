use std::net::{TcpStream, UdpSocket};

use hmac::Mac;
use x25519_dalek::PublicKey;

use crate::{hkdf::{HmacSha256, TranscriptHash}, premaster_secrets::PremasterSecret, secrets::{EarlySecrets, EcdhKeypair, HandshakeSecrets, MasterSecrets}, stream::TlsStream, wire::{CipherSuite, ClientHello, ContentType, Extension, Handshake, KeyShareEntry, NamedGroup, PacketReader, PlaintextError, ProtocolVersion, Random, TLSPlaintext}};

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

fn main() {
    println!("Hello, world!");

    let stream = TcpStream::connect("www.rust-lang.org:443").unwrap();
    dbg!(stream.local_addr().unwrap());
    let mut stream = TlsStream::new(stream);

    let mut ecdh = Some(EcdhKeypair::generate());

    let mut transcript_hash = TranscriptHash::new();

    let client_hello = Handshake::ClientHello(ClientHello {
        random: Random::new_from_rng(),
        cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
        extensions: vec![
            Extension::SupportedVersions {
                versions: vec![ProtocolVersion(0x0304)]
            },
            Extension::ServerName {
                host_names: vec!["www.rust-lang.org".to_owned()],
            },
            Extension::SupportedGroups {
                named_group_list: vec![NamedGroup::X25519],
            },
            Extension::KeyShare {
                client_shares: vec![
                    KeyShareEntry {
                        group: NamedGroup::X25519,
                        key_exchange: ecdh.as_ref().unwrap().public.as_bytes().into(),
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
    println!("{:?}", client_hello_bytes);

    let client_hello_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        fragment: client_hello_bytes,
    };
    stream.send_record(&client_hello_record).unwrap();

    let psk = [0; 32];
    let early_secrets = EarlySecrets::generate(&psk);
    println!("Early secret: {:?}", early_secrets.early_secret);

    let mut handshake_secrets: Option<HandshakeSecrets> = None;
    let mut master_secrets: Option<MasterSecrets> = None;

    let mut rx_counter = 0_u64;
    let mut tx_counter = 0_u64;

    loop {
        let record = stream.recv_record();
        dbg!(record.content_type);

        let mut r = PacketReader::new(record.fragment);

        match record.content_type {
            ContentType::Invalid => todo!(),
            ContentType::ChangeCipherSpec => {
                eprintln!("ignoring ChangeCipherSpec");
                //break;
            }
            ContentType::Alert => todo!(),
            ContentType::Handshake => {
                transcript_hash.add_message(&r.data);

                let handshake = dbg!(Handshake::from_bytes(&mut r).unwrap());
                assert!(r.finished());

                println!("{:?}", handshake);

                if let Handshake::ServerHello(sh) = handshake {
                    let mut shared = None;

                    for ext in &sh.extensions {
                        if let Extension::KeyShare { client_shares } = ext {
                            shared = Some(&client_shares[0]);
                        }
                    }

                    let shared = shared.unwrap();
                    let server_pk: [u8; 32] = shared.key_exchange[..].try_into().unwrap();

                    let server_pubkey = PublicKey::from(server_pk);
                    eprintln!("Server pubkey: {:?}", server_pubkey);
                    
                    let handshake = HandshakeSecrets::generate(&early_secrets, ecdh.take().unwrap(), &server_pubkey, &transcript_hash);
                    println!("Handshake secret: {:?}", handshake.handshake_secret);

                    handshake_secrets = Some(handshake);
                } else {
                    println!("{:?}", handshake);
                }
            }
            ContentType::ApplicationData => {
                if let Some(master_secrets) = master_secrets.as_ref() {
                    let plaintext = TLSPlaintext::decrypt(r.data, &master_secrets.server_write_key, rx_counter);
                    println!("{:?}", plaintext);

                    rx_counter += 1;

                    if plaintext.content_type == ContentType::ApplicationData {
                        dbg!(std::str::from_utf8(&plaintext.fragment));
                    } else if plaintext.content_type == ContentType::Handshake {
                        let data = b"\
                            GET / HTTP/1.1\r\n\
                            Host: www.rust-lang.org\r\n\
                            User-Agent: SalixTLS\r\n\
                            \r\n\
                            \r\n\
                            ";
                           
                        let data = TLSPlaintext {
                            content_type: ContentType::ApplicationData,
                            fragment: data.into(),
                        }.encrypt(&master_secrets.client_write_key, tx_counter);

                        let payload = TLSPlaintext {
                            content_type: ContentType::ApplicationData,
                            fragment: data,
                        };

                        stream.send_record(&payload).unwrap();
                    }

                } else if let Some(handshake_secrets) = handshake_secrets.as_ref() {
                    let plaintext = TLSPlaintext::decrypt(r.data, &handshake_secrets.server_write_key, rx_counter);
                    assert_eq!(plaintext.content_type, ContentType::Handshake);

                    rx_counter += 1;

                    let mut r = PacketReader::new(plaintext.fragment);
                    let h = Handshake::from_bytes(&mut r).unwrap();

                    println!("{:?}", h);

                    if let Handshake::Finished(hmac) = h {
                        let finished_key: [u8; 32] = hkdf::expand_label(&handshake_secrets.server_handshake_traffic_secret, b"finished", b"", 32).try_into().unwrap();

                        let ts = transcript_hash.compute();

                    	let mut mac = <HmacSha256 as Mac>::new_from_slice(&finished_key).unwrap();
                        mac.update(&ts);
                        mac.verify(&hmac.into()).unwrap();

                        transcript_hash.add_message(&r.data);

                        // TODO: Does this include the Finished message?
                        let ms = MasterSecrets::generate(handshake_secrets, &transcript_hash);
                        master_secrets = Some(ms);

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

                        stream.send_record(&payload).unwrap();

                    } else {
                        transcript_hash.add_message(&r.data);
                    }
                } else {
                    panic!();
                }
            }
        }
    }

    //query_dns();
}
