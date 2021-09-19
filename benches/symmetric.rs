//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use entre_nous::{init, Result, SymmetricKey};
use rand::RngCore;

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
    let pkt = key.encrypt(msg, Some(128 * 1024))?;
    key.decrypt(&pkt)
}

pub fn symmetric(c: &mut Criterion) {
    init().expect("Should always initialize");
    let small_messages = [32, 128, 512, 2048, 8192, 32 * 1024]
        .iter()
        .map(|s| generate_test_message(*s))
        .collect::<Vec<Vec<u8>>>();
    let large_messages = [128 * 1024, 512 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024]
        .iter()
        .map(|s| generate_test_message(*s))
        .collect::<Vec<Vec<u8>>>();

    let key = SymmetricKey::new();

    let mut small_messages_group = c.benchmark_group("Symmetric encryption - small messages");
    for message in small_messages {
        small_messages_group.bench_with_input(
            BenchmarkId::new("Box", format!("{} byte payload", message.len())),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_box(black_box(&m), black_box(&key))),
        );
        small_messages_group.bench_with_input(
            BenchmarkId::new(
                "Streaming - single chunk",
                format!("{} byte payload", message.len()),
            ),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_streaming(black_box(&m), black_box(&key))),
        );
    }
    small_messages_group.finish();

    let mut large_messages_group = c.benchmark_group("Symmetric encryption - large messages");
    for message in large_messages {
        large_messages_group.bench_with_input(
            BenchmarkId::new("Box", format!("{} byte payload", message.len())),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_box(black_box(&m), black_box(&key))),
        );
        large_messages_group.bench_with_input(
            BenchmarkId::new(
                "Streaming - single chunk",
                format!("{} byte payload", message.len()),
            ),
            &(&message, key.clone()),
            |b, (m, key)| b.iter(|| encrypt_decrypt_streaming(black_box(&m), black_box(&key))),
        );
        large_messages_group.bench_with_input(
            BenchmarkId::new(
                "Streaming - 128kB chunks",
                format!("{} byte payload", message.len()),
            ),
            &(&message, key.clone()),
            |b, (m, key)| {
                b.iter(|| encrypt_decrypt_streaming_chunked(black_box(&m), black_box(&key)))
            },
        );
    }
    large_messages_group.finish();
}

criterion_group!(benches, symmetric);
criterion_main!(benches);
