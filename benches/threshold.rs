use airbnb_creds::signature::{aggregate, partial_sign};
use airbnb_creds::{threshold_keygen, PublicParams};
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

// Threshold pairs (t, n) where t is the threshold and n is the total number of shares/signers.
const THRESHOLDS: &[(usize, usize)] = &[(2, 3), (3, 5), (5, 8), (10, 15), (100, 150)];

fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_aggregate");
    let mut rng = ark_std::test_rng();

    for &(t, n) in THRESHOLDS {
        let params = PublicParams::setup(5, &mut rng);
        let (shares, _) = threshold_keygen(&params, n, t, &mut rng);
        let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let partials: Vec<_> = shares[..t]
            .iter()
            .map(|share| {
                (
                    share.index,
                    partial_sign(&params, share, &messages, &mut rng)
                        .expect("partial signing failed"),
                )
            })
            .collect();

        group.bench_with_input(BenchmarkId::new("t_n", format!("{t}_{n}")), &partials, |b, partials| {
            b.iter(|| aggregate(black_box(partials)).expect("aggregation failed"));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_aggregate);
criterion_main!(benches);
