use airbnb_creds::commitment::{commit, open, roots_to_coeffs, CommitGroup};
use airbnb_creds::PublicParams;
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;


#[test]
fn test_commit_partial_opening() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);

    let rev_indices = vec![0, 2];
    let (c, c_hid) = open(&params, &messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1).unwrap();

    // Compute p_Rev(x) = ∏_{i ∈ Rev} (x − M[i]) and evaluate it in the h2 exponent
    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();
    let h2_p_rev = h2_message_poly(&params, &rev_messages);

    // Pairing check: e(C, g2) == e(C_hid, h2^{p_Rev(τ)})
    let lhs = Bls12_381::pairing(c.as_g1().unwrap(), params.g2);
    let rhs = Bls12_381::pairing(c_hid.as_g1().unwrap(), h2_p_rev);

    assert_eq!(lhs, rhs, "pairing check failed");
}

#[test]
fn test_commit_partial_opening_g2_hidden() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (c, c_hid) = open(
        &params,
        &messages,
        &a,
        &rev_indices,
        None,
        CommitGroup::G1,
        CommitGroup::G2,
    )
    .unwrap();
    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();
    let c_rev = commit(&params, &rev_messages, &Fr::from(1u64), CommitGroup::G1)
        .unwrap()
        .as_g1()
        .unwrap();

    let lhs = Bls12_381::pairing(c.as_g1().unwrap(), params.g2);
    let rhs = Bls12_381::pairing(c_rev, c_hid.as_g2().unwrap());

    assert_eq!(lhs, rhs, "G2-hidden opening pairing check failed");
}

#[test]
fn test_commit_reveal_all() {
    let mut rng = ark_std::test_rng();
    let l = 3;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);

    let rev_indices: Vec<usize> = (0..l).collect(); // reveal everything
    let (c, c_hid) = open(&params, &messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1).unwrap();

    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();
    let h2_p_rev = h2_message_poly(&params, &rev_messages);

    let lhs = Bls12_381::pairing(c.as_g1().unwrap(), params.g2);
    let rhs = Bls12_381::pairing(c_hid.as_g1().unwrap(), h2_p_rev);

    assert_eq!(lhs, rhs, "pairing check failed with all messages revealed");
}

#[test]
fn test_commit_open_none() {
    let mut rng = ark_std::test_rng();
    let l = 4;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);

    let (c, c_hid) = open(&params, &messages, &a, &[], None, CommitGroup::G1, CommitGroup::G1).unwrap();

    // p_Rev = empty product = 1, so h2^{p_Rev(τ)} = h2^1 = h2
    let h2_p_rev = h2_message_poly(&params, &Vec::<Fr>::new());
    assert_eq!(h2_p_rev, params.h2, "h2^1 should equal h2");

    let lhs = Bls12_381::pairing(c.as_g1().unwrap(), params.g2);
    let rhs = Bls12_381::pairing(c_hid.as_g1().unwrap(), h2_p_rev);

    assert_eq!(lhs, rhs, "pairing check failed with no messages revealed");
}

#[test]
fn test_commit_empty_set() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(4, &mut rng);
    let a = Fr::rand(&mut rng);

    // p_M(x) = 1 for the empty set, so C = h1^{a·1} = h1^a
    let c = commit(&params, &[], &a, CommitGroup::G1).unwrap().as_g1().unwrap();
    let expected = (G1Projective::from(params.h1) * a).into_affine();
    assert_eq!(c, expected);
}

/// Computes the polynomial in the powers-of-tau in h2 for a set of messages.
fn h2_message_poly(params: &PublicParams, messages: &Vec<Fr>) -> G2Affine {
    let coeffs = roots_to_coeffs(&messages);
    let degree = messages.len();
    let bases: Vec<G2Affine> = std::iter::once(params.h2)
        .chain(params.h2_tau[..degree].iter().copied())
        .collect();
    G2Projective::msm(&bases, &coeffs).unwrap().into_affine()
}
