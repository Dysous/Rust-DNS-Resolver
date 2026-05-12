use server::packet::*;
#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&id.to_be_bytes());
        buffer.extend_from_slice(&[0x01, 0x00]);
        buffer.extend_from_slice(&[0x00, 0x01]);
        buffer.extend_from_slice(&[0x00, 0x00]);
        buffer.extend_from_slice(&[0x00, 0x00]);
        buffer.extend_from_slice(&[0x00, 0x00]);

        for x in domain.split('.') {
            buffer.push(x.len() as u8);
            buffer.extend_from_slice(x.as_bytes());
        }
        buffer.push(0x00);

        buffer.extend_from_slice(&qtype.to_be_bytes());

        buffer.extend_from_slice(&[0x00, 0x01]);

        buffer
    }


    fn build_response(id: u16, domain: &str, ip: [u8; 4], ttl:u32) -> Vec<u8> {
        let mut buffer = build_query(id, domain, 1);

        buffer[6] = 0x00;
        buffer[7] = 0x01;

        buffer[2] = 0x81;
        buffer[3] = 0x80;


        for x in domain.split('.') {
            buffer.push(x.len() as u8);
            buffer.extend_from_slice(x.as_bytes());
        }

        buffer.push(0x00);

        buffer.extend_from_slice(&[0x00, 0x01]);
        buffer.extend_from_slice(&[0x00, 0x01]);
        buffer.extend_from_slice(&ttl.to_be_bytes());
        buffer.extend_from_slice(&[0x00, 0x04]);
        buffer.extend_from_slice(&[0x00, 0x01]);

        buffer
    }

    #[test]
    fn buffer_read_single_byte() {
        let data = [0xE9, 0x4C];
        let mut buffer = BytePacketBuffer::new(&data);
        assert_eq!(buffer.read(), 0xE9);
        assert_eq!(buffer.pos, 1);
    }

    #[test]
    fn buffer_read_u16_big_endian() {
        let data = [0xE9, 0x46];
        let mut buffer = BytePacketBuffer::new(&data);
        assert_eq!(buffer.read_u16(), 0xE946);
    }

    #[test]
    fn buffer_read_past_end_returns_zero() {
        let data = [0xFF];
        let mut buffer = BytePacketBuffer::new(&data);
        buffer.read();
        assert_eq!(buffer.read_u16(), 0x00);
    }

    #[test]
    fn buffer_write_overflow_returns_error() {
        let mut buffer  = BytePacketBuffer::new(&[]);
        buffer.pos = 512;
        assert!(buffer.write(0x01).is_err());
    }

    #[test]
    fn buffer_write_name_encodes_correct() {
        let mut buffer = BytePacketBuffer::new(&[]);
        buffer.write_name("google.com").unwrap();
        assert_eq!(buffer.buf[0], 6);
        assert_eq!(&buffer.buf[1..7], b"google");
        assert_eq!(buffer.buf[7], 3);
        assert_eq!(&buffer.buf[8..11], b"com");
        assert_eq!(buffer.buf[11], 0);
    }

    #[test]
    fn parses_question_and_name_and_time() {
        let raw = build_query(0x7777, "google.com", 1);
        let packet = DnsPacket::from_bytes(&raw);
        assert_eq!(packet.header.id, 0x7777);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "google.com");
        assert_eq!(packet.questions[0].qtype, 1);
        assert_eq!(packet.questions[0].qclass, 1);

    }


}