use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rdp::core::global::{NewFastPathUpdate, ts_fp_update};
use rdp::model::data::Message;

fn criterion_benchmark(c: &mut Criterion) {
    let mut data: Vec<u8> = vec![
        0x1, // header
        0xf, 0x0, // data length
        0x1, 0x1, 0x1, 0x1,
        0x2, 0x2, 0x2, 0x2,
        0x3, 0x3, 0x3, 0x3,
        0x4, 0x4, 0x4, 0x4,
        0x4, 0x3, 0x2, 0x1,
        0x0, 0x0, 0x0, 0x1,
    ];

    let mut group = c.benchmark_group("structures");

    group.bench_function("old", |b| b.iter(|| {
        let mut fp = ts_fp_update();
        let raw = &mut data;
        // let ff = NewFastPathUpdate::from_buffer(&mut &raw[..]);
        fp.read(&mut &raw[..]).unwrap();
    }));

    group.bench_function("new", |b| b.iter(|| {
        let raw = &mut data;
        NewFastPathUpdate::from_buffer(&mut &raw[..]);
        // .read(&mut &raw[..]).unwrap();
    }));



    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
