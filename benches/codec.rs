extern crate criterion;
extern crate rdp;

use criterion::{criterion_group, criterion_main, Criterion};
use rdp::core::event::BitmapEvent;


fn criterion_benchmark(c: &mut Criterion) {
    let data = std::fs::read("./src/codec/rle/testdata/bitmap-1672166010032.in").unwrap();

    let bitmap = BitmapEvent {
        dest_left: 0,
        dest_right: 0,
        dest_bottom: 0,
        dest_top: 0,
        width: 64,
        height: 64,
        is_compress: true,
        bpp: 32,
        data,
    };

    let mut result = vec![0 as u8; bitmap.width as usize * bitmap.height as usize * 4];

    let mut group = c.benchmark_group("bitmap decompress");

    group.bench_function("with allocation", |b| b.iter_with_large_drop(|| bitmap.decompress()));
    group.bench_function("without allocation", |b| b.iter(|| bitmap.decompress_to_buffer(&mut result)));

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
