use std::{io::{self, Read, Write}, net::TcpStream};

use crate::wire::{PacketReader, PlaintextError, TLSPlaintext};

pub struct TlsRecordStream {
	pub socket: TcpStream,
	pub buffer: PacketReader,
}

impl TlsRecordStream {
	pub fn new(socket: TcpStream) -> Self {
		TlsRecordStream {
			socket,
			buffer: PacketReader::new(Vec::new()),
		}
	}

	fn read_from_socket(&mut self, max_count: usize) -> usize {
		let old_len = self.buffer.data.len();
		self.buffer.data.resize(old_len + max_count, 0);
		let num_read = self.socket.read(&mut self.buffer.data[old_len..]).unwrap();
		self.buffer.data.truncate(old_len + num_read);
		num_read
	}

	fn read_exact_from_socket(&mut self, count: usize) {
        eprintln!("Reading new data of size {}", count);
		let old_len = self.buffer.data.len();
		self.buffer.data.resize(old_len + count, 0);
		self.socket.read_exact(&mut self.buffer.data[old_len..]).unwrap();
	}

	pub fn recv_record(&mut self) -> TLSPlaintext {
		if self.buffer.remaining() < 5 {
			self.read_exact_from_socket(5);
		}

		loop {
	        match TLSPlaintext::from_bytes(&mut self.buffer) {
	            Ok(record) => break record,
	            Err(PlaintextError::Other(err)) => panic!("{:?}", err),
	            Err(PlaintextError::NotEnoughData(missing)) => {
					self.read_exact_from_socket(missing);
	            }
	        }
		}
	}

	pub fn send_record(&mut self, record: &TLSPlaintext) -> io::Result<()> {
		let bytes = record.to_bytes();
		self.socket.write_all(&bytes)
	}
}