use bitfield::bitfield;

bitfield! {
    #[derive(Clone, Copy)]
    pub struct MessageFlags(u16);
    impl Debug;

    pub qr, set_qr: 0;
    pub opcode, set_opcode: 4, 1;
    pub aa, set_aa: 5;
    pub tc, set_tc: 6;
    pub rd, set_rd: 7;
    pub ra, set_ra: 8;
    pub z, _: 11, 9;
    pub rcode, set_rcode: 15, 12;
}

#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub identification: u16,
    pub flags: MessageFlags,
    pub num_questions: u16,
    pub num_answer_rrs: u16,
    pub num_authority_rrs: u16,
    pub num_additional_rrs: u16,
}

impl MessageHeader {
    pub fn query(identification: u16, num_questions: u16) -> Self {
        let mut flags = MessageFlags(0);
        flags.set_ra(true);

        Self {
            identification,
            flags,
            num_questions,
            num_answer_rrs: 0,
            num_authority_rrs: 0,
            num_additional_rrs: 0,
        }
    }

    pub fn to_bytes(self) -> [u8; 12] {
        let mut result = [0; 12];
        result[ 0.. 2].copy_from_slice(&self.identification.to_be_bytes());
        result[ 2.. 4].copy_from_slice(&self.flags.0.to_be_bytes());
        result[ 4.. 6].copy_from_slice(&self.num_questions.to_be_bytes());
        result[ 6.. 8].copy_from_slice(&self.num_answer_rrs.to_be_bytes());
        result[ 8..10].copy_from_slice(&self.num_authority_rrs.to_be_bytes());
        result[10..12].copy_from_slice(&self.num_additional_rrs.to_be_bytes());
        result
    }

    pub fn from_bytes(b: [u8; 12]) -> Self {
        Self {
            identification: u16::from_be_bytes(b[0..2].try_into().unwrap()),
            flags: MessageFlags(u16::from_be_bytes(b[2..4].try_into().unwrap())),
            num_questions: u16::from_be_bytes(b[4..6].try_into().unwrap()),
            num_answer_rrs: u16::from_be_bytes(b[6..8].try_into().unwrap()),
            num_authority_rrs: u16::from_be_bytes(b[8..10].try_into().unwrap()),
            num_additional_rrs: u16::from_be_bytes(b[10..12].try_into().unwrap()),
        }
    }
}

pub fn parse_name(mut b: &[u8]) -> (String, &[u8]) {
    let mut name = Vec::new();

    loop {
        let len = b[0] as usize;
        b = &b[1..];
        if len == 0 {
            break;
        }
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend_from_slice(&b[..len]);
        b = &b[len..];
    }

    (String::from_utf8(name).unwrap(), b)
}

pub fn parse_label(mut b: &[u8]) -> ((), &[u8]) {
    if b[0] & 0xC0 == 0xC0 {
        let offset = u16::from_be_bytes(b[0..2].try_into().unwrap()) & 0x3FFF;
        dbg!(offset);
        ((), &b[2..])
    } else {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub ty: u16,
    pub class: u16,
}


impl Question {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        for part in self.name.split('.') {
            let len: u8 = part.len().try_into().unwrap();
            result.push(len);
            result.extend_from_slice(part.as_bytes());
        }
        result.push(0); // Terminate NAME

        result.extend_from_slice(&self.ty.to_be_bytes());
        result.extend_from_slice(&self.class.to_be_bytes());

        result
    }

    pub fn from_bytes(b: &[u8]) -> (Self, &[u8]) {
        let (name, b) = parse_name(b);
        let ty = u16::from_be_bytes(b[0..2].try_into().unwrap());
        let class = u16::from_be_bytes(b[2..4].try_into().unwrap());

        (Self { name, ty, class }, &b[4..])
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    name: (),
    ty: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn from_bytes(b: &[u8]) -> (Self, &[u8]) {
        let (name, b) = parse_label(b);
        let ty = u16::from_be_bytes(b[0..2].try_into().unwrap());
        let class = u16::from_be_bytes(b[2..4].try_into().unwrap());
        let ttl = u32::from_be_bytes(b[4..8].try_into().unwrap());
        let rdlength = u16::from_be_bytes(b[8..10].try_into().unwrap());
        let rdata = b[10..][..rdlength as usize].to_owned();

        let b = &b[10 + rdlength as usize..];

        (ResourceRecord { name, ty, class, ttl, rdata }, b)
    }
}
