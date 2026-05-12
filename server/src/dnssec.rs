use ring::signature::{EcdsaKeyPair, KeyPair};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DNSSEC_ALGORITHM_ECDSAP256: u8 = 13;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_DNSKEY: u16 = 48;

pub struct DnssecSigner {
    pub key_pair: EcdsaKeyPair,
    pub key_tag: u16,
}

impl DnssecSigner {
    pub fn new(key_pair: EcdsaKeyPair) -> Self {
        let public_key = key_pair.public_key().as_ref();

        // Build the DNSKEY RDATA to calculate the real key tag
        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&256u16.to_be_bytes()); // Flags: Zone Key
        dnskey_rdata.push(3);
        dnskey_rdata.push(DNSSEC_ALGORITHM_ECDSAP256);         //mathematical algorithm to sign
        dnskey_rdata.extend_from_slice(public_key);

        let key_tag = calculate_key_tag(&dnskey_rdata);

        Self { key_pair, key_tag }
    }

    //signs response that is sent to client
    pub fn sign_response(&self, mut packet_bytes: Vec<u8>, domain_wire: &[u8]) -> Vec<u8> {
    //pub fn sign_response(&self, packet_bytes: &[u8], domain_wire: &[u8]) -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();


        //signature
        let sig = self.key_pair.sign(&rng, &packet_bytes).expect("Signing failed");

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // Type Covered (A)
        rdata.push(DNSSEC_ALGORITHM_ECDSAP256);
        rdata.push(domain_wire.iter().filter(|&&b| b > 0 && b < 32).count() as u8); // Label count
        rdata.extend_from_slice(&3600u32.to_be_bytes());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        rdata.extend_from_slice(&(now + 86400).to_be_bytes());
        rdata.extend_from_slice(&now.to_be_bytes());
        rdata.extend_from_slice(&self.key_tag.to_be_bytes());
        rdata.extend_from_slice(domain_wire);
        rdata.extend_from_slice(sig.as_ref());

        let mut rrsig_record = Vec::new();
        rrsig_record.extend_from_slice(domain_wire);
        rrsig_record.extend_from_slice(&TYPE_RRSIG.to_be_bytes());
        rrsig_record.extend_from_slice(&1u16.to_be_bytes());
        rrsig_record.extend_from_slice(&3600u32.to_be_bytes());
        rrsig_record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rrsig_record.extend_from_slice(&rdata);

        packet_bytes.extend_from_slice(&rrsig_record);

        let mut anc = u16::from_be_bytes([packet_bytes[6], packet_bytes[7]]);
        anc += 1;
        let anc_bytes = anc.to_be_bytes();
        packet_bytes[6] = anc_bytes[0];
        packet_bytes[7] = anc_bytes[1];

        packet_bytes
    }

    //builds dnskey response
    pub fn build_dnskey_answer(&self, request: &[u8], domain_wire: &[u8]) -> Vec<u8> {
        let mut response = request.to_vec();

        // Set Header: QR=1, AA=1, RD=1, RA=1
        response[2] = 0x85; response[3] = 0x80;
        // Set ANCOUNT = 1, NSCOUNT=0, ARCOUNT=0
        response[6] = 0x00; response[7] = 0x01;
        response[8] = 0x00; response[9] = 0x00;
        response[10] = 0x00; response[11] = 0x00;

        let public_key = self.key_pair.public_key().as_ref();
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&256u16.to_be_bytes());
        rdata.push(3);
        rdata.push(DNSSEC_ALGORITHM_ECDSAP256);
        rdata.extend_from_slice(public_key);

        let mut answer = Vec::new();
        answer.extend_from_slice(domain_wire);
        answer.extend_from_slice(&TYPE_DNSKEY.to_be_bytes());
        answer.extend_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&3600u32.to_be_bytes());
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(&rdata);

        response.extend_from_slice(&answer);
        response
    }
}

//identifies which public key was used
fn calculate_key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        ac += if i % 2 == 0 { (byte as u32) << 8 } else { byte as u32 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

//converts domain name into DNS wire format
pub fn name_to_wire(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for part in name.split('.') {
        wire.push(part.len() as u8);
        wire.extend_from_slice(part.as_bytes());
    }
    wire.push(0);
    wire
}