//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use entre_nous::{init, Result, SymmetricKey};
use rand::RngCore;

const CHUNK_SIZE: usize = 256 * 1024;

fn generate_test_message(size: usize) -> Vec<u8> {
    let mut msg = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut msg);
    msg
}

fn encrypt_decrypt_box(msg: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    let pkt = key.encrypt_box(msg);
    key.decrypt_box(&pkt)
}

fn encrypt_decrypt_streaming(msg: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    let pkt = key.encrypt(msg, None)?;
    key.decrypt(&pkt)
}

fn encrypt_decrypt_streaming_chunked(msg: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    let pkt = key.encrypt(msg, Some(CHUNK_SIZE))?;
    key.decrypt(&pkt)
}

pub fn symmetric(c: &mut Criterion) {
    init().expect("Should always initialize");
    let messages = [
        8192,
        32 * 1024,
        128 * 1024,
        512 * 1024,
        2 * 1024 * 1024,
        8 * 1024 * 1024,
    ]
    .iter()
    .map(|s| generate_test_message(*s))
    .collect::<Vec<Vec<u8>>>();

    let key = SymmetricKey::new();

    let mut group = c.benchmark_group("Symmetric key cryptography");
    for message in messages {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("Secretbox", message.len()),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_box(black_box(&m), black_box(&key))),
        );
        group.bench_with_input(
            BenchmarkId::new("Secretstream - no chunking", message.len()),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_streaming(black_box(&m), black_box(&key))),
        );
        group.bench_with_input(
            BenchmarkId::new("Secretstream - 256kB chunks", message.len()),
            &(&message, key.clone()),
            |b, (m, key)| {
                b.iter(|| encrypt_decrypt_streaming_chunked(black_box(&m), black_box(&key)))
            },
        );
    }
    group.finish();
}

criterion_group!(symmetric_benches, symmetric);
criterion_main!(symmetric_benches);
