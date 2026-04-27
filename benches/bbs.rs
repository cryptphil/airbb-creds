use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use bbs_plus::proof_23::PoKOfSignature23G1Protocol;
use bbs_plus::setup::{KeypairG2, SignatureParams23G1};
use bbs_plus::signature_23::Signature23G1;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::Rng;
use std::collections::BTreeMap;
use std::hint::black_box;

type E = Bls12_381;

struct BenchSetup {
    params: SignatureParams23G1<E>,
    keypair: KeypairG2<E>,
    messages: Vec<Fr>,
    sig: Signature23G1<E>,
}

const NUM_ATTR: &[usize] = &[1, 2, 10, 25, 50, 100];

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs/signing");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = setup(l, &mut rng);
            b.iter(|| {
                Signature23G1::<E>::new(
                    &mut rng,
                    black_box(&setup.messages),
                    black_box(&setup.keypair.secret_key),
                    black_box(&setup.params),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

// Blind signing while revealing half of the attributes.
fn bench_blind_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs/blind_signing");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = setup(l, &mut rng);

            // Split messages to first half hidden (i.e., committed), second half known to signer.
            let hidden_count = l / 2;
            // Contains a vector of index-message pairs for the hidden messages.
            let hidden: Vec<(usize, &Fr)> = setup.messages[..hidden_count]
                .iter()
                .enumerate()
                .collect();
            let commitment = setup.params
                .commit_to_messages(hidden)
                .expect("commit failed");
            // Expects the revealed messages as an ordered map of index-message pairs.
            let revealed: BTreeMap<usize, &Fr> = setup.messages[hidden_count..]
                .iter()
                .enumerate()
                .map(|(i, m)| (hidden_count + i, m))
                .collect();

            b.iter(|| {
                Signature23G1::<E>::new_with_committed_messages(
                    &mut rng,
                    black_box(&commitment),
                    black_box(revealed.clone()),
                    black_box(&setup.keypair.secret_key),
                    black_box(&setup.params),
                ).expect("blind_sign failed");
            });
        });
    }

    group.finish();
}

// Creating a presentation while revealing half of the attributes.
fn bench_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs/present");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = setup(l, &mut rng);
            let rev_limit = (l / 2).max(1);
            let rev_indices: Vec<usize> = (0..rev_limit).collect();
            let challenge = Fr::rand(&mut rng);

            b.iter(|| {
                let msgs_and_blindings = setup.messages.iter().enumerate().map(|(i, msg)| {
                    if rev_indices.contains(&i) {
                        MessageOrBlinding::RevealMessage(msg)
                    } else {
                        MessageOrBlinding::BlindMessageRandomly(msg)
                    }
                });
                let protocol = PoKOfSignature23G1Protocol::<E>::init(
                    &mut rng,
                    None,
                    None,
                    black_box(&setup.sig),
                    black_box(&setup.params),
                    msgs_and_blindings,
                ).unwrap();

                protocol.gen_proof(black_box(&challenge)).unwrap()
            });
        });
    }
    group.finish();
}

// Verifying a presentation with half of the attributes being revealed.
fn bench_verify_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs/verify_present");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = setup(l, &mut rng);
            let rev_limit = (l / 2).max(1);
            let rev_indices: Vec<usize> = (0..rev_limit).collect();
            let challenge = Fr::rand(&mut rng);

            let msgs_and_blindings = setup.messages.iter().enumerate().map(|(i, msg)| {
                if rev_indices.contains(&i) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            });
            let protocol = PoKOfSignature23G1Protocol::<E>::init(
                &mut rng,
                None,
                None,
                &setup.sig,
                &setup.params,
                msgs_and_blindings,
            ).unwrap();
            let proof = protocol.gen_proof(&challenge).unwrap();

            let revealed_msgs: BTreeMap<usize, Fr> =
                rev_indices.iter().map(|&i| (i, setup.messages[i])).collect();

            b.iter_batched(
                || (setup.keypair.public_key.clone(), setup.params.clone()),
                |(pk, p)| {
                    proof.verify(black_box(&revealed_msgs), black_box(&challenge), pk, p).unwrap()
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn setup(l: usize, rng: &mut impl Rng) -> BenchSetup {
    let params = SignatureParams23G1::<E>::generate_using_rng(rng, l as u32);
    let keypair = KeypairG2::<E>::generate_using_rng_and_bbs23_params(rng, &params);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(rng)).collect();
    let sig = Signature23G1::<E>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
    BenchSetup { params, keypair, messages, sig }
}

criterion_group!(benches, bench_sign, bench_blind_sign, bench_present, bench_verify_present);
criterion_main!(benches);
