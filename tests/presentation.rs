use airbnb_creds::commitment::{open, CommitGroup};
use airbnb_creds::keys::keygen;
use airbnb_creds::presentation::{present, verify_present, verify_present_optimized, Credential, Presentation};
use airbnb_creds::signature::{aggregate, blind_partial_sign, blind_sign, sign, unblind, verify};
use airbnb_creds::{threshold_keygen, PublicParams};
use ark_bls12_381::Fr;
use ark_std::UniformRand;

#[test]
fn test_present_sel_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![0, 2];
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();
    let result_opt = verify_present_optimized(&params, &vk, &presentation, &mut rng).unwrap();

    assert!(result, "selectively-revealed presentation should verify");
    assert!(result_opt, "selectively-revealed presentation should verify (optimized)");
}

#[test]
fn blind_issued_credential_presentation_verifies() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);
    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let a = Fr::rand(&mut rng);
    let issuer_reveal_indices = vec![0, 2];
    let (com, com_hid) = open(
        &params,
        &attributes,
        &a,
        &issuer_reveal_indices,
        None,
        CommitGroup::G1,
        CommitGroup::G1,
    )
    .expect("opening failed");
    let revealed_to_issuer: Vec<Fr> = issuer_reveal_indices
        .iter()
        .map(|&i| attributes[i])
        .collect();
    let blind_sig = blind_sign(
        &params,
        &sk,
        &com,
        &com_hid,
        &revealed_to_issuer,
        &mut rng,
    )
    .expect("blind signing failed");
    let cred = Credential::new(unblind(&blind_sig, &a), attributes);

    let reveal_indices = vec![1, 3, 5];
    let aux = Fr::rand(&mut rng);
    let presentation = present(&params, &cred, &reveal_indices, &aux, &mut rng)
        .expect("presentation failed");

    assert!(
        verify_present(&params, &vk, &presentation).expect("verification failed"),
        "presentation of a blind-issued credential should verify"
    );
    assert!(
        verify_present_optimized(&params, &vk, &presentation, &mut rng)
            .expect("optimized verification failed"),
        "optimized presentation verification should succeed for a blind-issued credential"
    );
}

#[test]
fn blind_threshold_credential_presentation_verifies() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (shares, vk) = threshold_keygen(&params, 5, 3, &mut rng);
    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let a = Fr::rand(&mut rng);
    let issuer_reveal_indices = vec![0, 2];
    let (com, com_hid) = open(
        &params,
        &attributes,
        &a,
        &issuer_reveal_indices,
        None,
        CommitGroup::G1,
        CommitGroup::G2,
    )
    .expect("opening failed");
    let revealed_to_issuer: Vec<Fr> = issuer_reveal_indices
        .iter()
        .map(|&i| attributes[i])
        .collect();
    let partials: Vec<_> = shares[..3]
        .iter()
        .map(|share| {
            (
                share.index,
                blind_partial_sign(
                    &params,
                    share,
                    &com,
                    &com_hid,
                    &revealed_to_issuer,
                    &mut rng,
                )
                .expect("partial blind signing failed"),
            )
        })
        .collect();
    let signature = unblind(&aggregate(&partials).expect("aggregation failed"), &a);
    assert!(
        verify(&params, &vk, &attributes, &signature).expect("signature verification failed"),
        "blind threshold signature should verify"
    );
    assert!(
        verify_present_credential(&params, &vk, signature, attributes, &mut rng),
        "presentation of a blind threshold credential should verify"
    );
}

fn verify_present_credential(
    params: &PublicParams,
    vk: &airbnb_creds::VerificationKey,
    signature: airbnb_creds::Signature,
    attributes: Vec<Fr>,
    rng: &mut impl rand::Rng,
) -> bool {
    let cred = Credential::new(signature, attributes);
    let reveal_indices = vec![1, 3, 5];
    let aux = Fr::rand(rng);
    let presentation = present(params, &cred, &reveal_indices, &aux, rng).expect("presentation failed");

    verify_present(params, vk, &presentation).expect("verification failed")
        && verify_present_optimized(params, vk, &presentation, rng)
            .expect("optimized verification failed")
}

#[test]
fn test_present_full_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices: Vec<usize> = (0..l).collect();
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();
    let result_opt = verify_present_optimized(&params, &vk, &presentation, &mut rng).unwrap();

    assert!(result, "full-reveal presentation should verify");
    assert!(result_opt, "full-reveal presentation should verify (optimized)");
}

#[test]
fn test_present_no_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &[], &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();
    let result_opt = verify_present_optimized(&params, &vk, &presentation, &mut rng).unwrap();

    assert!(result, "zero-reveal presentation should verify");
    assert!(result_opt, "zero-reveal presentation should verify (optimized)");
}

#[test]
fn test_present_wrong_aux() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![1, 3];
    let aux = Fr::rand(&mut rng);
    let wrong_aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();

    let presentation_wrong_aux = Presentation {
        sig: presentation.sig,
        com: presentation.com,
        com_hid: presentation.com_hid,
        rev_attributes: presentation.rev_attributes,
        aux: wrong_aux,
    };

    let result = verify_present(&params, &vk, &presentation_wrong_aux).unwrap();
    let result_opt = verify_present_optimized(&params, &vk, &presentation_wrong_aux, &mut rng).unwrap();

    assert!(!result, "presentation with wrong aux should not verify");
    assert!(!result_opt, "presentation with wrong aux should not verify (optimized)");
}

#[test]
fn test_present_wrong_revealed_messages_fails() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![0, 1];
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();

    let wrong_rev_attrs = (0..rev_indices.len()).map(|_| Fr::rand(&mut rng)).collect();
    let presentation_bad_rev = Presentation {
        sig: presentation.sig,
        com: presentation.com,
        com_hid: presentation.com_hid,
        rev_attributes: wrong_rev_attrs,
        aux: presentation.aux,
    };

    let result = verify_present(&params, &vk, &presentation_bad_rev).unwrap();
    let result_opt = verify_present_optimized(&params, &vk, &presentation_bad_rev, &mut rng).unwrap();

    assert!(!result, "presentation with wrong revealed attributes should not verify");
    assert!(!result_opt, "presentation with wrong revealed attributes should not verify (optimized)");
}
