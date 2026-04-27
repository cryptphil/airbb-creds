use airbnb_creds::keys::keygen;
use airbnb_creds::presentation::{present, verify_present_optimized, Credential};
use airbnb_creds::signature::sign;
use airbnb_creds::PublicParams;
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;
use std::hint::black_box;

const NUM_ATTR: &[usize] = &[1, 2, 10, 25, 50, 100];

// Create a presentation while always revealing half of the attributes.
fn bench_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("present");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            let rev_indices: Vec<usize> = (0..l / 2).collect();
            let aux = Fr::rand(&mut rng);

            b.iter(|| {
                present(
                    black_box(&setup.params),
                    black_box(&setup.cred),
                    black_box(&rev_indices),
                    black_box(&aux),
                    &mut rng,
                )
                .expect("present failed");
            });
        });
    }

    group.finish();
}


fn bench_verify_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_present");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            let rev_indices: Vec<usize> = (0..(l / 2).max(1)).collect();
            let aux = Fr::rand(&mut rng);
            let presentation =
                present(&setup.params, &setup.cred, &rev_indices, &aux, &mut rng)
                    .expect("present failed");

            b.iter(|| {
                verify_present_optimized(
                    black_box(&setup.params),
                    black_box(&setup.vk),
                    black_box(&presentation),
                    black_box(&mut rng)
                )
                .expect("verify_present failed");
            });
        });
    }

    group.finish();
}

struct BenchSetup {
    params: PublicParams,
    cred: Credential,
    vk: airbnb_creds::keys::VerificationKey,
}

fn bench_setup(l: usize, rng: &mut impl Rng) -> BenchSetup {
    let params = PublicParams::setup(l, rng);
    let (sk, vk) = keygen(&params, rng);
    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(rng)).collect();
    let sig = sign(&params, &sk, &attributes, rng).expect("sign failed");
    let cred = Credential::new(sig, attributes);
    BenchSetup { params, cred, vk }
}

criterion_group!(benches, bench_present, bench_verify_present);
criterion_main!(benches);
