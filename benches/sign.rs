//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::cmp::min;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use entre_nous::{init, KeyPair, Result, SignatureStream};
use rand::RngCore;

const CHUNK_SIZE: usize = 256 * 1024;

fn generate_test_message(size: usize) -> Vec<u8> {
    let mut msg = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut msg);
    msg
}

fn sign_verify(msg: &[u8], key: &KeyPair) -> Result<()> {
    let sig = key.sign(msg);
    key.public_key().verify(&sig, msg)?;
    Ok(())
}

fn stream_sign_verify(msg: &[u8], key: &KeyPair) -> Result<()> {
    let mut stream = SignatureStream::new();
    let mut start = 0;
    while start < msg.len() {
        let end = min(start + CHUNK_SIZE, msg.len());
        stream.push(&msg[start..end]);
        start += CHUNK_SIZE;
    }
    let sig = stream.finalize(key.secret_key());

    let mut stream = SignatureStream::new();
    let mut start = 0;
    while start < msg.len() {
        let end = min(start + CHUNK_SIZE, msg.len());
        stream.push(&msg[start..end]);
        start += CHUNK_SIZE;
    }
    stream.verify(&sig, key.public_key())?;

    let sig = key.sign(msg);
    key.public_key().verify(&sig, msg)?;
    Ok(())
}

pub fn signing(c: &mut Criterion) {
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

    let key = KeyPair::new();

    let mut group = c.benchmark_group("Asymmetric key signatures");
    for message in messages {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("No streaming", message.len()),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| sign_verify(black_box(&m), black_box(&key))),
        );
        group.bench_with_input(
            BenchmarkId::new("Streaming (256kB chunks)", message.len()),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| stream_sign_verify(black_box(&m), black_box(&key))),
        );
    }
    group.finish();
}

criterion_group!(signing_benches, signing);
criterion_main!(signing_benches);
