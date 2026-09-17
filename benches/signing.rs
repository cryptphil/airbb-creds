use airbnb_creds::commitment::{open, CommitGroup};
use airbnb_creds::signature::{blind_sign, sign};
use airbnb_creds::{keygen, PublicParams};
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;
use std::hint::black_box;


const NUM_ATTR: &[usize] = &[1, 2, 10, 25, 50, 100];

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);

            b.iter(|| {
                sign(black_box(&setup.params), black_box(&setup.sk), black_box(&setup.messages), &mut rng).expect("signing failed");
            })
        } );
    }

    group.finish();

}

// Blind signing while revealing half of the attributes.
fn bench_blind_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blind_signing");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            // Always reveal half of the attributes for blind signing (at least one).
            let rev_limit = (l / 2).max(1);
            let rev_indices: Vec<usize> = (0..rev_limit).collect();
            let a = Fr::rand(&mut rng);
            let (com, com_hid) = open(&setup.params, &setup.messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1)
                .expect("open failed");
            let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| setup.messages[i]).collect();

            b.iter(|| {
                blind_sign(
                    black_box(&setup.params),
                    black_box(&setup.sk),
                    black_box(&com),
                    black_box(&com_hid),
                    black_box(&rev_messages),
                    &mut rng,
                )
                    .expect("blind_sign failed");
            });
        });
    }

    group.finish();
}

struct BenchSetup {
    params: PublicParams,
    messages: Vec<Fr>,
    sk: airbnb_creds::keys::SecretKey,
}

fn bench_setup(l: usize, rng: &mut impl Rng) -> BenchSetup {
    let params = PublicParams::setup(l, rng);
    let (sk, _vk) = keygen(&params, rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(rng)).collect();

    BenchSetup{params, messages, sk}
}


criterion_group!(benches, bench_signing, bench_blind_signing);

criterion_main!(benches);
