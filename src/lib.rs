//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod errors;
mod io_helpers;
mod sign;
mod symmetric;

pub use {
    errors::{Error, Result},
    sign::{verify, KeyPair, PublicKey, Signature, SignatureStream},
    symmetric::{Key as SymmetricKey, Packet},
};

use std::{
    convert::TryInto,
    mem::{size_of, size_of_val},
};

use crate::symmetric::{Header, ENCRYPTION_ADDITIONAL_BYTES, HEADER_BYTES};

pub struct Envelope {
    data: Packet,
    signature: Packet,
}

pub fn init() -> Result<()> {
    sodiumoxide::init().map_err(|_| Error::Initialization)
}

pub fn encrypt_and_sign(
    payload: &[u8],
    encryption_key: &SymmetricKey,
    signing_key: &KeyPair,
    chunk_size: Option<usize>,
) -> Result<Envelope> {
    let data = encryption_key.encrypt(payload, chunk_size)?;
    let sig = signing_key.sign(payload);
    let signature = encryption_key.encrypt(&sig.to_bytes(), None)?;
    Ok(Envelope { data, signature })
}

pub fn stream_encrypt_and_sign<D, S>(
    source: &mut S,
    dest: &mut D,
    encryption_key: &SymmetricKey,
    signing_key: &KeyPair,
    chunk_size: usize,
    max_read_bytes: Option<usize>,
) -> Result<Packet>
where
    S: std::io::Read + ?Sized,
    D: std::io::Write + ?Sized,
{
    let mut encryption_stream = encryption_key.init_encryption_stream()?;
    let mut signature_stream = SignatureStream::new();

    // Write header
    let header_bytes = io_helpers::write(dest, encryption_stream.header().as_ref())?;
    if header_bytes != HEADER_BYTES {
        return Err(Error::StreamingWrite);
    }

    // Write chunk size
    let chunk_size_bytes = io_helpers::write(dest, &chunk_size.to_le_bytes())?;
    if chunk_size_bytes != size_of_val(&chunk_size) {
        return Err(Error::StreamingWrite);
    }

    // Read and encrypt data chunks
    let max_read_bytes = max_read_bytes.unwrap_or(usize::MAX);
    let mut total_read_bytes = 0;

    let mut read_buffer = vec![0; chunk_size];
    let mut encryption_buffer = Vec::with_capacity(chunk_size + ENCRYPTION_ADDITIONAL_BYTES);
    while total_read_bytes < max_read_bytes {
        let read_bytes = if chunk_size != 0 {
            io_helpers::read(source, &mut read_buffer)?
        } else {
            read_buffer.clear();
            source.read_to_end(&mut read_buffer)?
        };
        if read_bytes == 0 {
            break;
        }
        let last_chunk = read_bytes < chunk_size;
        encryption_stream.push_to_vec(
            &read_buffer[..read_bytes],
            last_chunk,
            &mut encryption_buffer,
        )?;
        let written_bytes = io_helpers::write(dest, &encryption_buffer)?;
        if written_bytes != read_bytes + ENCRYPTION_ADDITIONAL_BYTES {
            return Err(Error::StreamingWrite);
        }
        signature_stream.push(&read_buffer[..read_bytes]);

        total_read_bytes += read_bytes;
    }

    let signature = signature_stream.finalize(signing_key.secret_key());

    let signature_packet = encryption_key.encrypt(&signature.to_bytes(), None)?;

    Ok(signature_packet)
}

pub fn decrypt_and_verify(
    envelope: &Envelope,
    decryption_key: &SymmetricKey,
    verification_key: &PublicKey,
) -> Result<Vec<u8>> {
    let cleartext = decryption_key.decrypt(&envelope.data)?;
    let sig = decryption_key.decrypt(&envelope.signature)?;
    let sig = Signature::new(&sig)?;
    verify(&verification_key, &sig, &cleartext[..])?;
    Ok(cleartext)
}

pub fn stream_decrypt_and_verify<S, D>(
    source: &mut S,
    dest: &mut D,
    signature_packet: &Packet,
    decryption_key: &SymmetricKey,
    verification_key: &PublicKey,
) -> Result<()>
where
    S: std::io::Read,
    D: std::io::Write,
{
    // Decrypt signature packet
    let signature_bytes = decryption_key.decrypt(signature_packet)?;
    let signature = Signature::new(&signature_bytes)?;

    // Read header
    let mut header_buffer = vec![0; HEADER_BYTES];
    let header_bytes = io_helpers::read(source, &mut header_buffer)?;
    if header_bytes != HEADER_BYTES {
        return Err(Error::StreamingRead);
    }
    let header = Header::from_slice(&header_buffer)?;

    // Read chunk size
    let mut chunk_size_buffer = vec![0; size_of::<usize>()];
    let chunk_size_bytes = io_helpers::read(source, &mut chunk_size_buffer)?;
    if chunk_size_bytes != size_of_val(&size_of::<usize>()) {
        return Err(Error::StreamingRead);
    }
    let chunk_size = usize::from_le_bytes(chunk_size_buffer.as_slice().try_into()?);

    // Read and decrypt ciphertext chunks
    let mut decryption_stream = decryption_key.init_decryption_stream(&header)?;
    let mut signature_stream = SignatureStream::new();

    let mut read_buffer = vec![0; chunk_size + ENCRYPTION_ADDITIONAL_BYTES];
    let mut decryption_buffer = Vec::with_capacity(chunk_size);
    while !decryption_stream.is_finalized() {
        let read_bytes = if chunk_size != 0 {
            io_helpers::read(source, &mut read_buffer)?
        } else {
            read_buffer.clear();
            source.read_to_end(&mut read_buffer)?
        };
        if read_bytes == 0 {
            break;
        }
        decryption_stream.pull_to_vec(&read_buffer[..read_bytes], &mut decryption_buffer)?;
        let written_bytes = io_helpers::write(dest, &decryption_buffer)?;
        if written_bytes + ENCRYPTION_ADDITIONAL_BYTES != read_bytes {
            return Err(Error::StreamingWrite);
        }
        signature_stream.push(&decryption_buffer[..written_bytes]);
    }

    signature_stream.verify(&signature, verification_key)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        proptest::prelude::*,
        std::{
            cmp::Ordering,
            io::{Read, Seek, SeekFrom, Write},
        },
        tempfile::tempfile,
    };

    use super::*;

    pub(crate) fn optional_chunk_size_strategy(
        max_chunk_size: usize,
    ) -> impl Strategy<Value = Option<usize>> {
        prop_oneof![Just(None), (0..max_chunk_size).prop_map(|v| Some(v)),].boxed()
    }

    pub(crate) fn message_strategy(max_message_size: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..max_message_size)
    }

    proptest! {
        #[test]
        fn encrypt_and_sign_then_decrypt_and_verify(
            chunk_size in optional_chunk_size_strategy(2000),
            msg in message_strategy(1000)
        ) {
            init()?;
            let signing_key = KeyPair::new();
            let encryption_key = SymmetricKey::new();

            let envelope = encrypt_and_sign(msg.as_slice(), &encryption_key, &signing_key, chunk_size)?;
            let msg_again = decrypt_and_verify(&envelope, &encryption_key, &signing_key.public_key())?;
            prop_assert_eq!(Ordering::Equal, msg.cmp(&msg_again));
        }

        #[test]
        fn mem_stream_encrypt_and_sign_then_decrypt_and_verify(
            chunk_size in 0..2000usize,
            msg in message_strategy(1000),
        ) {
            init()?;
            let signing_key = KeyPair::new();
            let encryption_key = SymmetricKey::new();

            let mut ciphertext = Vec::new();
            let signature_packet = stream_encrypt_and_sign(
                &mut (&msg[..]),
                &mut ciphertext,
                &encryption_key,
                &signing_key,
                chunk_size,
                None,
            )?;

            let mut msg_again = Vec::new();
            stream_decrypt_and_verify(
                &mut (&ciphertext[..]),
                &mut msg_again,
                &signature_packet,
                &encryption_key,
                &signing_key.public_key(),
            )?;
            prop_assert_eq!(Ordering::Equal, msg.cmp(&msg_again));
        }

        #[test]
    fn file_stream_encrypt_and_sign_then_decrypt_and_verify(
        chunk_size in 0..2000usize,
        msg in message_strategy(1000),
    ) {
        init()?;
        let signing_key = KeyPair::new();
        let encryption_key = SymmetricKey::new();

        let mut input_file = tempfile()?;
        input_file.write(&msg)?;
        input_file.seek(SeekFrom::Start(0))?;

        let mut ciphertext_file = tempfile()?;
        let signature_packet = stream_encrypt_and_sign(
            &mut input_file,
            &mut ciphertext_file,
            &encryption_key,
            &signing_key,
            chunk_size,
            None,
        )?;
        ciphertext_file.seek(SeekFrom::Start(0))?;

        let mut output_file = tempfile()?;
        stream_decrypt_and_verify(
            &mut ciphertext_file,
            &mut output_file,
            &signature_packet,
            &encryption_key,
            &signing_key.public_key(),
        )?;

        output_file.seek(SeekFrom::Start(0))?;

        let mut msg_again = Vec::new();
        output_file.read_to_end(&mut msg_again)?;

        prop_assert_eq!(Ordering::Equal, msg.cmp(&msg_again));
    }
    }
}
