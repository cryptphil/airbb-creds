use airbnb_creds::commitment::{open, CommitGroup};
use airbnb_creds::signature::{
    aggregate, blind_partial_sign, blind_sign, partial_sign, sign, unblind, verify,
};
use airbnb_creds::Error;
use airbnb_creds::{keygen, threshold_keygen, PublicParams};
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use rand::Rng;

#[test]
fn valid_signature_verifies() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let (sk, vk) = keygen(&params, &mut rng);
    let sig = sign(&params, &sk, &messages, &mut rng).expect("signing failed");

    let valid = verify(&params, &vk, &messages, &sig).expect("verify failed");
    assert!(valid, "valid signature failed to verify");
}

#[test]
fn different_messages_signature_fails() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let (sk, vk) = keygen(&params, &mut rng);
    let sig = sign(&params, &sk, &messages, &mut rng).expect("signing failed");

    // Change the message set at a random index.
    let mut diff_messages = messages.clone();
    let idx = rng.gen_range(0..l);
    diff_messages[idx] = Fr::rand(&mut rng);

    let valid = verify(&params, &vk, &diff_messages, &sig).expect("verify failed");
    assert!(!valid, "signature on different messages verified");
}

#[test]
fn wrong_key_signature_fails() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let (sk, _) = keygen(&params, &mut rng);
    let sig = sign(&params, &sk, &messages, &mut rng).expect("signing failed");

    let (_, wrong_vk) = keygen(&params, &mut rng);

    let valid = verify(&params, &wrong_vk, &messages, &sig).expect("verify failed");
    assert!(!valid, "signature verified under a different key");
}

#[test]
fn blind_issued_signature_unblinds_verifies() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let (sk, vk) = keygen(&params, &mut rng);

    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (com, com_hid) = open(&params, &messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1)
        .expect("opening failed");
    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();

    let blind_sig = blind_sign(&params, &sk, &com, &com_hid, &rev_messages, &mut rng)
        .expect("blind signing failed");
    let sig = unblind(&blind_sig, &a);

    assert!(
        verify(&params, &vk, &messages, &sig).expect("verification failed"),
        "unblinded blind-issued signature should verify"
    );
}

#[test]
fn blind_issued_signature_wrong_unblinding_fails() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let (sk, vk) = keygen(&params, &mut rng);

    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (com, com_hid) = open(&params, &messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1)
        .expect("opening failed");
    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();

    let blind_sig = blind_sign(&params, &sk, &com, &com_hid, &rev_messages, &mut rng)
        .expect("blind signing failed");
    let wrong_a = a + Fr::from(1u64);
    let sig = unblind(&blind_sig, &wrong_a);

    assert!(
        !verify(&params, &vk, &messages, &sig).expect("verification failed"),
        "signature unblinded with a wrong scalar should not verify"
    );
}

#[test]
fn blind_sign_wrong_revealed_messages_fails() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let (sk, _vk) = keygen(&params, &mut rng);

    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (com, com_hid) = open(&params, &messages, &a, &rev_indices, None, CommitGroup::G1, CommitGroup::G1).unwrap();

    // Provide a random set of messages as the set of revealed messages.
    let wrong_rev: Vec<Fr> = (0..2).map(|_| Fr::rand(&mut rng)).collect();

    let result = blind_sign(&params, &sk, &com, &com_hid, &wrong_rev, &mut rng);
    assert!(
        matches!(result, Err(Error::InvalidCommitmentOpeningBlindSign)),
        "expected InvalidCommitmentOpeningBlindSign, got: {:?}", result
    );
}

#[test]
fn blind_partial_sign_honest_opening_succeeds() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(5, &mut rng);
    let (shares, _) = threshold_keygen(&params, 3, 2, &mut rng);
    let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (com, com_hid) = open(
        &params,
        &messages,
        &a,
        &rev_indices,
        None,
        CommitGroup::G1,
        CommitGroup::G2,
    )
    .expect("opening failed");
    let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| messages[i]).collect();

    blind_partial_sign(
        &params,
        &shares[0],
        &com,
        &com_hid,
        &rev_messages,
        &mut rng,
    )
    .expect("partial blind signing failed");
}

#[test]
fn blind_partial_sign_wrong_revealed_messages_fails() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(5, &mut rng);
    let (shares, _) = threshold_keygen(&params, 3, 2, &mut rng);
    let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);
    let rev_indices = vec![0, 2];
    let (com, com_hid) = open(
        &params,
        &messages,
        &a,
        &rev_indices,
        None,
        CommitGroup::G1,
        CommitGroup::G2,
    )
    .expect("opening failed");
    let wrong_rev: Vec<Fr> = (0..rev_indices.len()).map(|_| Fr::rand(&mut rng)).collect();

    let result = blind_partial_sign(
        &params,
        &shares[0],
        &com,
        &com_hid,
        &wrong_rev,
        &mut rng,
    );
    assert!(
        matches!(result, Err(Error::InvalidCommitmentOpeningBlindSign)),
        "expected InvalidCommitmentOpeningBlindSign, got: {result:?}"
    );
}

#[test]
fn threshold_signature_verifies_at_threshold() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(5, &mut rng);
    let (shares, vk) = threshold_keygen(&params, 5, 3, &mut rng);
    let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let partials: Vec<_> = [0, 2, 4]
        .iter()
        .map(|&position| {
            let share = &shares[position];
            (
                share.index,
                partial_sign(&params, share, &messages, &mut rng).expect("partial signing failed"),
            )
        })
        .collect();

    let signature = aggregate(&partials).expect("aggregation failed");
    assert!(
        verify(&params, &vk, &messages, &signature).expect("verification failed"),
        "threshold signature should verify"
    );
}

#[test]
fn threshold_signature_verifies_above_threshold() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(5, &mut rng);
    let (shares, vk) = threshold_keygen(&params, 5, 3, &mut rng);
    let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let partials: Vec<_> = shares[..4]
        .iter()
        .map(|share| {
            (
                share.index,
                partial_sign(&params, share, &messages, &mut rng).expect("partial signing failed"),
            )
        })
        .collect();

    let signature = aggregate(&partials).expect("aggregation failed");
    assert!(
        verify(&params, &vk, &messages, &signature).expect("verification failed"),
        "threshold signature with more shares should verify"
    );
}

#[test]
fn threshold_signature_below_threshold_verification_fails() {
    let mut rng = ark_std::test_rng();
    let params = PublicParams::setup(5, &mut rng);
    let (shares, vk) = threshold_keygen(&params, 5, 3, &mut rng);
    let messages: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
    let partials: Vec<_> = shares[..2]
        .iter()
        .map(|share| {
            (
                share.index,
                partial_sign(&params, share, &messages, &mut rng).expect("partial signing failed"),
            )
        })
        .collect();

    let signature = aggregate(&partials).expect("aggregation failed");
    assert!(
        !verify(&params, &vk, &messages, &signature).expect("verification failed"),
        "a signature from fewer shares than the threshold should not verify"
    );
}
