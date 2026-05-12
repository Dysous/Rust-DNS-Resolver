//server/src/packet.rs
//sofia, josh code for week 1

use std::str;

//wrapper (cursor)
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}
impl BytePacketBuffer {
    pub fn new(data: &[u8]) -> Self {
        let mut buffer = BytePacketBuffer {
            buf: [0; 512],
            pos: 0
        };
        buffer.buf[..data.len()].copy_from_slice(data); //can overflow after 512 bytes, need fix
        buffer
    }

    pub fn read(&mut self) -> u8 {
        if self.pos >=512 {
            return 0;
        }
        let res = self.buf[self.pos];   //can cause issues in week3 with malformed packets
        self.pos += 1;
        res
    }

    pub fn read_u16(&mut self) -> u16 {
        u16::from_be_bytes([self.read(), self.read()])
    }

    pub fn get(&self, pos: usize) -> u8 { self.buf[pos] }   //can cause out of bound issues later

    pub fn write(&mut self, val: u8) -> Result<(), String>{
        if self.pos >= 512 {
            return Err("buffer overflow".to_string());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) {
        self.write((val >> 8) as u8);
        self.write((val & 0xFF) as u8);
    }

    pub fn write_name(&mut self, name: &str) -> Result<(), String>{
        for label in name.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(format!("Name length should be less than 63 chars"));
            }
            self.write(len as u8);

            for b in label.as_bytes() {
                self.write(*b);
            }
        }
        self.write(0);
        Ok(())
    }
}
//DNS packet parser/serializer
//STRUCTS: DNSHeader, DNSQuestion, DNSPacket
#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,                //id num
    pub flags: u16,             //flags (QR, Opcode, etc)
    pub qcount: u16,           //question count
    pub anscount: u16,           //answer count
    pub authcount: u16,           //authority count
    pub addcount: u16,           //additional count
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,       //domain name query, ex google.com
    pub qtype: u16,         //type of query, 1 for A recs, 28 for AAAA, may change this later
    pub qclass: u16,        //class of query
}

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,              //header containing metadata about entire packet
    pub questions: Vec<DnsQuestion>,    //list of specific domain name queries sent by client

    //DNSRecord is after week 1 work
    pub answers: Vec<DnsRecord>,        //list of resource records to answer clients questions
    pub authorities: Vec<DnsRecord>,    //not implemented uet
    pub additional: Vec<DnsRecord>,     //not impl yet
}

//DNSRECORD IS AFTER WEEK 1 NOT IMPLEMENTED YET
#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>, // change vec<u8> later when implement
}


//FUNCTIONS:
impl DnsHeader {
    pub fn read(buffer: &mut BytePacketBuffer) -> Self {
        DnsHeader {
            id: buffer.read_u16(),
            flags: buffer.read_u16(),
            qcount: buffer.read_u16(),
            anscount: buffer.read_u16(),
            authcount: buffer.read_u16(),
            addcount: buffer.read_u16(),
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) {
        buffer.write_u16(self.id);
        buffer.write_u16(self.flags);
        buffer.write_u16(self.qcount);
        buffer.write_u16(self.anscount);
        buffer.write_u16(self.authcount);
        buffer.write_u16(self.addcount);
    }
}

impl DnsQuestion {
    pub fn read(buffer: &mut BytePacketBuffer) -> Self {
        DnsQuestion {
            name: DnsPacket::parse_name(buffer),
            qtype: buffer.read_u16(),
            qclass: buffer.read_u16(),
        }
    }


    pub fn write(&self, buffer: &mut BytePacketBuffer) {
        let _ = buffer.write_name(&self.name);
        buffer.write_u16(self.qtype);
        buffer.write_u16(self.qclass);
    }


}
impl DnsPacket {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut buffer = BytePacketBuffer::new(data);
        let header = DnsHeader::read(&mut buffer);

        let mut questions = Vec::new();
        for _ in 0..header.qcount {
            questions.push(DnsQuestion::read(&mut buffer));
        }
        let mut answers = Vec::new();
        for _ in 0..header.anscount {
            answers.push(DnsRecord::read(&mut buffer));
        }

        let mut authorities = Vec::new();
        for _ in 0..header.authcount {
            authorities.push(DnsRecord::read(&mut buffer));
        }

        let mut additional = Vec::new();
        for _ in 0..header.addcount {
            additional.push(DnsRecord::read(&mut buffer));
        }

        DnsPacket {
            header,
            questions,
            answers,
            authorities,
            additional,
        }
    }
    pub fn parse_name(buffer: &mut BytePacketBuffer) -> String {
        let mut labels = Vec::new();
        let mut pos = buffer.pos;
        let mut jumped = false;
        let mut max_jumps = 5; //prevent infinite loops

        loop {
            if max_jumps == 0 { break; }
            let len = buffer.get(pos);

            if len & 0xC0 == 0xC0 {
                if !jumped { buffer.pos = pos + 2; }
                let b2 = buffer.get(pos + 1) as usize;
                pos = (((len as usize) ^ 0xC0) << 8) | b2;
                jumped = true;
                max_jumps -= 1;
                continue;
            }

            pos += 1;
            if len == 0 { break; }

            let label = &buffer.buf[pos..pos + len as usize];
            labels.push(str::from_utf8(label).unwrap().to_string());
            pos += len as usize;
        }

        if !jumped { buffer.pos = pos; }
        labels.join(".")
    }




    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        };

        self.header.write(&mut buffer);

        for question in &self.questions {
            question.write(&mut buffer);
        }
        //let len = data.len().min(512);
        buffer.buf[..buffer.pos].to_vec()   //week 1 logic, will overflow after 512 bytes later
    }
}

// reads a DNS resource record from the packet buffer
// resource records appear in the answer, authority, and additional
// sections of a DNS packet and contain the actual response data
impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Self {
        let name = DnsPacket::parse_name(buffer);
        let rtype = buffer.read_u16();
        let class = buffer.read_u16();
        let ttl = u32::from_be_bytes([
            buffer.read(),
            buffer.read(),
            buffer.read(),
            buffer.read(),
        ]);

        let data_len = buffer.read_u16() as usize;
        let mut data = Vec::with_capacity(data_len);

        for _ in 0..data_len {
            data.push(buffer.read());
        }
        DnsRecord {
            name,
            rtype,
            class,
            ttl,
            data,
        }
    }
}
