use crate::commitment::{commit, open, CommitGroup, Commitment};
use crate::{Error, PublicParams, Signature, VerificationKey};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::{Field, One};
use ark_std::UniformRand;
use rand::Rng;

/// A credential is a signature together with the set of signed attributes.
pub struct Credential {
    pub(crate) sig: Signature,
    pub(crate) attributes: Vec<Fr>,
}

impl Credential {
    pub fn new(sig: Signature, attributes: Vec<Fr>) -> Self {
        Self { sig, attributes }
    }
}

/// Represents a credential presentation for a subset of revealed attributes.
pub struct Presentation {
    /// Re-randomized signature (σ′₁, σ′₂).
    pub sig: Signature,
    /// Full commitment `C = h2^{a₁·p_M(τ)}` in G2.
    pub com: Commitment,
    /// Commitment on the hidden attributes `C_hid = g1^{a₁·p_hid(τ)·(τ−aux)}` in G1.
    pub com_hid: Commitment,
    /// The revealed attributes.
    pub rev_attributes: Vec<Fr>,
    /// Auxiliary data bound into `C_hid` (e.g. a nonce or context).
    pub aux: Fr,
}

/// Creates a credential presentation while selectively revealing the subset of attributes at `rev_indices`.
///
/// `aux` is auxiliary data agreed upon out-of-band between holder and verifier (e.g. the verifier identity, 
//  a nonce, or session context). It is bound into C_hid, preventing the presentation from being replayed for
/// a different `aux`.
///
/// # Presentation Protocol
///
/// 1. Sample scalars `a₀, a₁ ←$ Zp`.
/// 2. Randomize the signature:
///    ```text
///    σ′₁ = σ₁ · h1^{a₀·p_M(τ)}
///    σ′₂ = (σ₂ · g1^{a₀})^{1/a₁}
///    ```
/// 3. Compute the commitments:
///    ```text
///    C     = h2^{a₁·p_M(τ)}
///    C_hid = g1^{a₁·p_hid(τ)·(τ − aux)}
///    ```
/// 4. Return the presentation proof (σ₁', σ₂', C, C_hid).
pub fn present(
    params: &PublicParams,
    cred: &Credential,
    reveal_indices: &[usize],
    aux: &Fr,
    rng: &mut impl Rng
) -> Result<Presentation, Error> {
    let a0 = Fr::rand(rng);
    let a1 = Fr::rand(rng);
    let a1_inv = a1.inverse().ok_or(Error::ZeroScalar)?;
    let (com, com_hid) = open(params, &cred.attributes, &a1, reveal_indices, Some(aux), CommitGroup::G2)?;

    // Compute σ₁' = σ₁ * h1^{a0·p_M(τ)}}
    let h1msg = commit(params, &cred.attributes, &a0, CommitGroup::G1)?
        .as_g1().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G1 })?;
    let s1prime = (cred.sig.sigma1 + h1msg).into_affine();

    // Compute σ₂' = (σ₂ * g1^a1) ^ {1/a0}
    let s2a1 = cred.sig.sigma2 + G1Projective::from(params.g1) * a0;
    let s2prime = (s2a1 * a1_inv).into_affine();

    Ok(Presentation {
        sig: Signature { sigma1: s1prime, sigma2: s2prime },
        com,
        com_hid,
        rev_attributes: reveal_indices.iter().map(|&i| cred.attributes[i]).collect(),
        aux: *aux,
    })
}


/// Verify a credential presentation revealing a set of attributes bound to some auxiliary data against `vk`.
///
/// Checks two pairing equations:
/// 1. Commitment is valid for the revealed messages: `e(g1^{τ−aux}, C) == e(C_hid, h2^{p_{M_rev}(τ)})`
/// 2. Signature is valid: `e(σ₁', g2) == vk · e(σ₂', C)`
pub fn verify_present(params: &PublicParams, vk: &VerificationKey, presentation: &Presentation) -> Result<bool, Error> {
    let rev_h2 = commit(params, &presentation.rev_attributes, &Fr::one(), CommitGroup::G2)?
        .as_g2().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G2 })?;
    // g1^(τ-aux)
    let aux_g1 = (params.g1_tau[0] + params.g1 * (-presentation.aux)).into_affine();

    // Check e(g1^(τ-aux), C) = e(C_hid, h2^{p_{M_rev}(τ)})
    let com = presentation.com.as_g2().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G2 })?;
    let com_hid = presentation.com_hid.as_g1().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G1 })?;
    let lhs_com: PairingOutput<Bls12_381> = Bls12_381::pairing(aux_g1, com.clone());
    let rhs_com: PairingOutput<Bls12_381> = Bls12_381::pairing(com_hid, rev_h2);

    // e(σ₁', g2) == vk · e(σ₂', C)
    let lhs_sig: PairingOutput<Bls12_381> = Bls12_381::pairing(presentation.sig.sigma1, params.g2);
    let rhs_sig = PairingOutput::<Bls12_381>(vk.0) +
        Bls12_381::pairing(presentation.sig.sigma2, com);

    Ok(lhs_com == rhs_com && lhs_sig == rhs_sig)
}

/// The optimized version of the presentation verification algorithm with one pairing less.
pub fn verify_present_optimized(params: &PublicParams, vk: &VerificationKey, presentation: &Presentation, rng: &mut impl Rng) -> Result<bool, Error> {
    let gamma = Fr::rand(rng);
    let rev_h2 = commit(params, &presentation.rev_attributes, &Fr::one(), CommitGroup::G2)?
        .as_g2().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G2 })?;
    // g1^((τ-aux)*γ)
    let aux_g1 = (params.g1_tau[0] + params.g1 * (-presentation.aux)) * gamma;

    let com = presentation.com.as_g2().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G2 })?;
    let com_hid = presentation.com_hid.as_g1().ok_or(Error::CommitmentWrongGroup { exp_group: CommitGroup::G1 })?;

    // Check e(σ₁', g2) * e(C_hid, h2^{p_{M_rev}(τ)})^γ = vk · e(σ₂' * g1^((τ-aux)*γ), C)
    let lhs_sig: PairingOutput<Bls12_381> = Bls12_381::pairing(presentation.sig.sigma1, params.g2);
    let lhs_com: PairingOutput<Bls12_381> = Bls12_381::pairing(com_hid, rev_h2) * gamma;
    let lhs = lhs_sig + lhs_com;
    let rhs = PairingOutput::<Bls12_381>(vk.0) +
        Bls12_381::pairing(presentation.sig.sigma2 + aux_g1, com);

    Ok(lhs == rhs)
}
