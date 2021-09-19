//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::cmp::min;

use sodiumoxide::crypto::{
    secretbox::{gen_nonce, open, seal, Key as BoxKey, Nonce as SodiumNonce},
    secretstream::{
        gen_key, Header as SodiumHeader, Key as StreamKey, Pull, Push, Stream, Tag, ABYTES,
        HEADERBYTES,
    },
};

use crate::errors::{Error, Result};

pub const ENCRYPTION_ADDITIONAL_BYTES: usize = ABYTES;
pub const HEADER_BYTES: usize = HEADERBYTES;

pub struct Nonce(SodiumNonce);

pub struct Packet {
    header: Header,
    chunk_size: Option<usize>,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct Header(SodiumHeader);

impl Header {
    pub fn from_slice(b: &[u8]) -> Result<Header> {
        Ok(Header(
            SodiumHeader::from_slice(b).ok_or(Error::InvalidSliceSize)?,
        ))
    }
}

impl AsRef<[u8]> for Header {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct BoxPacket {
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

pub struct EncryptionStream {
    stream: Stream<Push>,
    header: Header,
}

impl EncryptionStream {
    pub fn push(&mut self, payload: &[u8], final_push: bool) -> Result<Vec<u8>> {
        let tag = if final_push { Tag::Final } else { Tag::Message };
        self.stream
            .push(payload, None, tag)
            .map_err(|_| Error::StreamingEncryptionPush)
    }

    pub fn push_to_vec(
        &mut self,
        payload: &[u8],
        final_push: bool,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let tag = if final_push { Tag::Final } else { Tag::Message };
        self.stream
            .push_to_vec(payload, None, tag, out)
            .map_err(|_| Error::StreamingEncryptionPush)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
}

pub struct DecryptionStream {
    stream: Stream<Pull>,
}

impl DecryptionStream {
    pub fn pull(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (decrypted, _tag) = self
            .stream
            .pull(ciphertext, None)
            .map_err(|_| Error::StreamingDecryptionPull)?;
        Ok(decrypted)
    }

    pub fn pull_to_vec(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let _tag = self
            .stream
            .pull_to_vec(ciphertext, None, out)
            .map_err(|_| Error::StreamingDecryptionPull)?;
        Ok(())
    }

    pub fn is_finalized(&self) -> bool {
        self.stream.is_finalized()
    }
}

#[derive(Clone)]
pub struct Key {
    key: StreamKey,
}

impl Key {
    pub fn new() -> Key {
        let key = gen_key();
        Key { key }
    }

    pub fn encrypt(&self, payload: &[u8], chunk_size: Option<usize>) -> Result<Packet> {
        let mut stream = self.init_encryption_stream()?;
        let num_chunks = num_chunks_in_cleartext(payload.len(), chunk_size);
        let mut output = Packet {
            header: *stream.header(),
            chunk_size,
            ciphertext: Vec::with_capacity(
                payload.len() + num_chunks * ENCRYPTION_ADDITIONAL_BYTES,
            ),
        };
        match chunk_size {
            Some(chunk_size) if chunk_size > 0 => {
                let mut buf = Vec::new();
                let mut start = 0;
                loop {
                    let end = min(start + chunk_size, payload.len());
                    let last_chunk = end == payload.len();
                    stream.push_to_vec(&payload[start..end], last_chunk, &mut buf)?;
                    output.ciphertext.extend_from_slice(buf.as_slice());
                    start += chunk_size;
                    if start >= payload.len() {
                        break;
                    }
                }
            }
            _ => stream.push_to_vec(payload, true, &mut output.ciphertext)?,
        };
        Ok(output)
    }

    pub fn decrypt(&self, packet: &Packet) -> Result<Vec<u8>> {
        let mut stream = self.init_decryption_stream(&packet.header)?;
        let encrypted_chunk_size = match packet.chunk_size {
            Some(chunk_size) if chunk_size > 0 => chunk_size + ENCRYPTION_ADDITIONAL_BYTES,
            _ => packet.ciphertext.len(),
        };
        let mut buf = Vec::new();
        let mut payload = Vec::new();
        let mut start = 0;
        while !stream.is_finalized() {
            let end = min(start + encrypted_chunk_size, packet.ciphertext.len());
            stream.pull_to_vec(&packet.ciphertext[start..end], &mut buf)?;
            payload.extend_from_slice(&buf);
            start += encrypted_chunk_size;
        }
        Ok(payload)
    }

    pub fn encrypt_box(&self, payload: &[u8]) -> BoxPacket {
        let box_key = BoxKey::from_slice(&self.key.as_ref()).unwrap();
        let sodium_nonce = gen_nonce();
        let ciphertext = seal(payload, &sodium_nonce, &box_key);
        BoxPacket {
            nonce: Nonce(sodium_nonce),
            ciphertext,
        }
    }

    pub fn decrypt_box(&self, packet: &BoxPacket) -> Result<Vec<u8>> {
        let box_key = BoxKey::from_slice(&self.key.as_ref()).unwrap();
        let Nonce(sodium_nonce) = &packet.nonce;
        open(packet.ciphertext.as_slice(), &sodium_nonce, &box_key).map_err(|_| Error::Verification)
    }

    pub fn init_encryption_stream(&self) -> Result<EncryptionStream> {
        let (enc_stream, header) =
            Stream::init_push(&self.key).map_err(|_| Error::StreamingEncryptionInit)?;
        Ok(EncryptionStream {
            stream: enc_stream,
            header: Header(header),
        })
    }

    pub fn init_decryption_stream(&self, header: &Header) -> Result<DecryptionStream> {
        let stream =
            Stream::init_pull(&header.0, &self.key).map_err(|_| Error::StreamingDecryptionInit)?;
        Ok(DecryptionStream { stream })
    }
}

fn num_chunks_in_cleartext(payload_size: usize, chunk_size: Option<usize>) -> usize {
    match chunk_size {
        Some(chunk_size) => {
            if chunk_size == 0 {
                return 1;
            }
            (payload_size as f64 / chunk_size as f64).ceil().abs() as usize
        }
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use proptest::prelude::*;

    use super::*;
    use crate::{
        init,
        tests::{message_strategy, optional_chunk_size_strategy},
    };

    proptest! {
        #[test]
        fn encrypt_and_decrypt_box(msg in message_strategy(1000)) {
            init()?;
            let key = Key::new();
            let pkt = key.encrypt_box(msg.as_slice());
            let msg_again = key.decrypt_box(&pkt)?;
            prop_assert_eq!(Ordering::Equal, msg.cmp(&msg_again));
        }

        #[test]
        fn encrypt_and_decrypt_stream(
            chunk_size in optional_chunk_size_strategy(2000),
            msg in message_strategy(1000)
        ) {
            init()?;
            let key = Key::new();
            let pkt = key.encrypt(msg.as_slice(), chunk_size)?;
            let msg_again = key.decrypt(&pkt)?;
            prop_assert_eq!(Ordering::Equal, msg.cmp(&msg_again));
        }
    }

    #[test]
    fn encrypt_and_decrypt_streams() -> Result<()> {
        init()?;
        let msg = "VERY LONG MESSAGE".as_bytes();
        let key = Key::new();
        let mut enc_stream = key.init_encryption_stream()?;
        let c1 = enc_stream.push(&msg[..10], false)?;
        let c2 = enc_stream.push(&msg[10..], true)?;
        let mut dec_stream = key.init_decryption_stream(&enc_stream.header())?;
        let m1 = dec_stream.pull(&c1)?;
        let m2 = dec_stream.pull(&c2)?;
        assert_eq!(Ordering::Equal, msg.cmp([m1, m2].concat().as_slice()));
        Ok(())
    }

    #[test]
    fn test_num_chunks_in_cleartext() {
        assert_eq!(num_chunks_in_cleartext(5, None), 1);
        assert_eq!(num_chunks_in_cleartext(5, Some(0)), 1);
        assert_eq!(num_chunks_in_cleartext(5, Some(2)), 3);
        assert_eq!(num_chunks_in_cleartext(4, Some(2)), 2);
        assert_eq!(num_chunks_in_cleartext(5, Some(10)), 1);
    }
}
