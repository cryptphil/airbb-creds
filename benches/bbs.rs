use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use bbs_plus::proof_23::PoKOfSignature23G1Protocol;
use bbs_plus::setup::{KeypairG2, SignatureParams23G1};
use bbs_plus::signature_23::Signature23G1;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::Rng;
use schnorr_pok::{compute_random_oracle_challenge, SchnorrCommitment, SchnorrResponse};
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

// Blind signing while revealing half of the attributes and letting the signer verify the user's
// knowledge of all messages in the commitment using a Schnorr PoK.
fn bench_blind_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs/blind_signing");
    let mut rng = ark_std::test_rng();

    for &l in NUM_ATTR {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = setup(l, &mut rng);

            // First half hidden (committed), second half revealed to signer.
            let hidden_count = (l / 2).min(l - 1);
            let hidden_msgs: Vec<Fr> = setup.messages[..hidden_count].to_vec();
            // Bases for the hidden messages: params.h[0..hidden_count]
            let hidden_bases: Vec<G1Affine> = setup.params.h[..hidden_count].to_vec();
            let hidden_pairs: Vec<(usize, &Fr)> = hidden_msgs.iter().enumerate().collect();
            let commitment = setup.params
                .commit_to_messages(hidden_pairs)
                .expect("commit failed");
            let revealed: BTreeMap<usize, &Fr> = setup.messages[hidden_count..]
                .iter()
                .enumerate()
                .map(|(i, m)| (hidden_count + i, m))
                .collect();

            let pok = commitment_pok(&hidden_bases, &hidden_msgs, &commitment, &mut rng);

            b.iter(|| {
                // First verify knowledge of the committed messages and then sign the commitment.
                pok.response
                    .is_valid(&hidden_bases, black_box(&commitment), &pok.rand_com, &pok.challenge)
                    .expect("Commitment PoK verification failed");
                Signature23G1::<E>::new_with_committed_messages(
                    &mut rng,
                    black_box(&commitment),
                    black_box(revealed.clone()),
                    black_box(&setup.keypair.secret_key),
                    black_box(&setup.params),
                ).expect("blind_sign failed")
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


struct CommitmentPoK {
    rand_com: G1Affine,
    challenge: Fr,
    response: SchnorrResponse<G1Affine>,
}

// Computes a PoK of the committed messages using a Schnorr DLOG proof with SHA256.
fn commitment_pok(
    bases: &[G1Affine],
    messages: &[Fr],
    commitment: &G1Affine,
    rng: &mut impl Rng,
) -> CommitmentPoK {
    let blindings: Vec<Fr> = (0..bases.len()).map(|_| Fr::rand(rng)).collect();
    let sc_comm = SchnorrCommitment::new(bases, blindings);
    let mut bytes = Vec::new();
    commitment.serialize_compressed(&mut bytes).unwrap();
    sc_comm.t.serialize_compressed(&mut bytes).unwrap();
    let challenge = compute_random_oracle_challenge::<Fr, sha2::Sha256>(&bytes);
    let response = sc_comm.response(messages, &challenge).unwrap();
    CommitmentPoK { rand_com: sc_comm.t, challenge, response }
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
