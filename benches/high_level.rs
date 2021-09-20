//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use entre_nous::{
    decrypt, encrypt, init, stream_decrypt, stream_encrypt, KeyPair, Result, SymmetricKey,
};
use rand::RngCore;

const CHUNK_SIZE: usize = 256 * 1024;

fn generate_test_message(size: usize) -> Vec<u8> {
    let mut msg = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut msg);
    msg
}

fn encrypt_decrypt(msg: &[u8], encryption_key: &SymmetricKey) -> Result<()> {
    let envelope = encrypt(msg, encryption_key, None, Some(CHUNK_SIZE))?;
    decrypt(&envelope, encryption_key, None)?;
    Ok(())
}

fn encrypt_decrypt_signed(
    msg: &[u8],
    encryption_key: &SymmetricKey,
    signing_key: &KeyPair,
) -> Result<()> {
    let envelope = encrypt(msg, encryption_key, Some(signing_key), Some(CHUNK_SIZE))?;
    decrypt(&envelope, encryption_key, Some(signing_key.public_key()))?;
    Ok(())
}

fn stream_encrypt_decrypt(msg: &[u8], encryption_key: &SymmetricKey) -> Result<()> {
    let mut ciphertext = Vec::new();
    stream_encrypt(
        &mut &msg[..],
        &mut ciphertext,
        encryption_key,
        None,
        CHUNK_SIZE,
        None,
    )?;
    let mut cleartext = Vec::new();
    stream_decrypt(
        &mut &ciphertext[..],
        &mut cleartext,
        None,
        encryption_key,
        None,
    )?;
    Ok(())
}

fn stream_encrypt_decrypt_signed(
    msg: &[u8],
    encryption_key: &SymmetricKey,
    signing_key: &KeyPair,
) -> Result<()> {
    let mut ciphertext = Vec::new();
    let signature_packet = stream_encrypt(
        &mut &msg[..],
        &mut ciphertext,
        encryption_key,
        Some(signing_key),
        CHUNK_SIZE,
        None,
    )?;
    let mut cleartext = Vec::new();
    stream_decrypt(
        &mut &ciphertext[..],
        &mut cleartext,
        signature_packet.as_ref(),
        encryption_key,
        Some(signing_key.public_key()),
    )?;
    Ok(())
}

pub fn high_level(c: &mut Criterion) {
    init().expect("Should always initialize");
    let messages = [128 * 1024, 512 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024]
        .iter()
        .map(|s| generate_test_message(*s))
        .collect::<Vec<Vec<u8>>>();

    let encryption_key = SymmetricKey::new();
    let signing_key = KeyPair::new();

    let mut group = c.benchmark_group(format!("High-level API (Chunk size: {} bytes)", CHUNK_SIZE));
    for message in messages {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("Without signatures", message.len()),
            &(&message, encryption_key.clone()),
            |b, (m, encryption_key)| {
                b.iter(|| encrypt_decrypt(black_box(&m), black_box(&encryption_key)))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Without signatures (stream)", message.len()),
            &(&message, encryption_key.clone()),
            |b, (m, encryption_key)| {
                b.iter(|| stream_encrypt_decrypt(black_box(&m), black_box(&encryption_key)))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("With signatures", message.len()),
            &(&message, encryption_key.clone(), signing_key.clone()),
            |b, (m, encryption_key, signing_key)| {
                b.iter(|| {
                    encrypt_decrypt_signed(
                        black_box(&m),
                        black_box(&encryption_key),
                        black_box(&signing_key),
                    )
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("With signatures (stream)", message.len()),
            &(&message, encryption_key.clone(), signing_key.clone()),
            |b, (m, encryption_key, signing_key)| {
                b.iter(|| {
                    stream_encrypt_decrypt_signed(
                        black_box(&m),
                        black_box(&encryption_key),
                        black_box(&signing_key),
                    )
                })
            },
        );
    }
    group.finish();
}

criterion_group!(high_level_benches, high_level);
criterion_main!(high_level_benches);
