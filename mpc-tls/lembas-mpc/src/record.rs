//! TLS 1.2 AES-128-GCM records with keys this side holds: what the borrower
//! runs after taking the keys out of rustls, continuing from the sequence
//! numbers rustls reached (plus one on the client side, for the pool's
//! record).

use aes_gcm::{Aes128Gcm, NewAead, aead::AeadInPlace};
use anyhow::{Result, bail, ensure};

/// Largest plaintext a single TLS record may carry.
pub const MAX_RECORD_PLAINTEXT: usize = 1 << 14;

/// Record content types.
pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const ALERT: u8 = 0x15;
pub const HANDSHAKE: u8 = 0x16;
pub const APPLICATION_DATA: u8 = 0x17;

/// The `close_notify` alert: warning level, description 0.
pub const CLOSE_NOTIFY: [u8; 2] = [1, 0];

const EXPLICIT_NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;

/// The TLS 1.2 traffic keys.
#[derive(Clone)]
pub struct TrafficKeys {
    /// Client write key.
    pub client_write_key: [u8; 16],
    /// Client write IV (implicit nonce part).
    pub client_write_iv: [u8; 4],
    /// Server write key.
    pub server_write_key: [u8; 16],
    /// Server write IV (implicit nonce part).
    pub server_write_iv: [u8; 4],
}

impl std::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficKeys").finish_non_exhaustive()
    }
}

/// The additional data AES-GCM authenticates for a TLS 1.2 record.
pub fn tls12_aad(seq: u64, typ: u8, len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = typ;
    aad[9] = 0x03;
    aad[10] = 0x03;
    aad[11..].copy_from_slice(&(len as u16).to_be_bytes());
    aad
}

/// Both directions of the record layer.
pub struct LocalRecordLayer {
    keys: TrafficKeys,
    writer: LocalRecordWriter,
    reader: LocalRecordReader,
}

impl LocalRecordLayer {
    /// Creates a record layer continuing from the given sequence numbers.
    pub fn new(keys: &TrafficKeys, write_seq: u64, read_seq: u64) -> Self {
        Self {
            keys: keys.clone(),
            writer: LocalRecordWriter::new(keys, write_seq),
            reader: LocalRecordReader::new(keys, read_seq),
        }
    }

    pub fn keys(&self) -> &TrafficKeys {
        &self.keys
    }

    /// Encrypts one record and returns it encoded, ready for the wire.
    pub fn encrypt(&mut self, typ: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.writer.encrypt(typ, plaintext)
    }

    /// Decrypts one encoded record received from the server.
    pub fn decrypt(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        self.reader.decrypt(record)
    }

    /// Splits into the sending and the receiving half.
    pub fn split(self) -> (LocalRecordWriter, LocalRecordReader) {
        (self.writer, self.reader)
    }
}

/// Encrypts records to the server under the client write key.
pub struct LocalRecordWriter {
    cipher: Aes128Gcm,
    iv: [u8; 4],
    seq: u64,
}

impl LocalRecordWriter {
    fn new(keys: &TrafficKeys, seq: u64) -> Self {
        Self {
            cipher: Aes128Gcm::new((&keys.client_write_key).into()),
            iv: keys.client_write_iv,
            seq,
        }
    }

    /// Encrypts one record and returns it encoded, ready for the wire. The
    /// explicit nonce is the sequence number, as rustls does it.
    pub fn encrypt(&mut self, typ: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() <= MAX_RECORD_PLAINTEXT,
            "record plaintext too long: {} > {MAX_RECORD_PLAINTEXT}",
            plaintext.len()
        );
        let seq = self.seq;
        self.seq += 1;

        let explicit_nonce = seq.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let aad = tls12_aad(seq, typ, plaintext.len());

        let mut body = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, &mut body)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;

        let len = EXPLICIT_NONCE_LEN + body.len() + TAG_LEN;
        let mut record = Vec::with_capacity(5 + len);
        record.extend_from_slice(&[typ, 0x03, 0x03]);
        record.extend_from_slice(&(len as u16).to_be_bytes());
        record.extend_from_slice(&explicit_nonce);
        record.extend_from_slice(&body);
        record.extend_from_slice(&tag);
        Ok(record)
    }
}

/// Decrypts records from the server under the server write key.
pub struct LocalRecordReader {
    cipher: Aes128Gcm,
    iv: [u8; 4],
    seq: u64,
}

impl LocalRecordReader {
    fn new(keys: &TrafficKeys, seq: u64) -> Self {
        Self {
            cipher: Aes128Gcm::new((&keys.server_write_key).into()),
            iv: keys.server_write_iv,
            seq,
        }
    }

    /// Decrypts one whole encoded record (5-byte header included).
    pub fn decrypt(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        ensure!(record.len() >= 5, "record too short");
        let typ = record[0];
        ensure!(record[1] == 0x03, "not a TLS record");
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        ensure!(record.len() == 5 + len, "record length mismatch");
        let payload = &record[5..];
        if payload.len() < EXPLICIT_NONCE_LEN + TAG_LEN {
            bail!("ciphertext record is too short");
        }
        let (explicit_nonce, rest) = payload.split_at(EXPLICIT_NONCE_LEN);
        let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);

        let seq = self.seq;
        self.seq += 1;

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv);
        nonce[4..].copy_from_slice(explicit_nonce);
        let aad = tls12_aad(seq, typ, ciphertext.len());

        let mut plaintext = ciphertext.to_vec();
        self.cipher
            .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
            .map_err(|_| anyhow::anyhow!("tag verification failed"))?;
        Ok((typ, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_both_halves() {
        let keys = TrafficKeys {
            client_write_key: [1; 16],
            client_write_iv: [2; 4],
            server_write_key: [1; 16],
            server_write_iv: [2; 4],
        };
        // The server's reader is the client's writer with the keys swapped,
        // so with identical keys a writer at seq n decrypts with a reader at n.
        let mut writer = LocalRecordLayer::new(&keys, 7, 0);
        let mut reader = LocalRecordLayer::new(&keys, 0, 7);
        let record = writer.encrypt(APPLICATION_DATA, b"hello").unwrap();
        assert_eq!(record[0], APPLICATION_DATA);
        assert_eq!(record.len(), 5 + 8 + 5 + 16);
        assert_eq!(reader.decrypt(&record).unwrap(), (APPLICATION_DATA, b"hello".to_vec()));
        // Wrong sequence number: the tag fails.
        let record = writer.encrypt(ALERT, &CLOSE_NOTIFY).unwrap();
        let mut skipped = LocalRecordLayer::new(&keys, 0, 9);
        assert!(skipped.decrypt(&record).is_err());
        assert_eq!(reader.decrypt(&record).unwrap(), (ALERT, CLOSE_NOTIFY.to_vec()));
    }
}
