use crate::commitment::{commit, CommitGroup, Commitment};
use crate::error::Error;
use crate::keys::{SecretKey, VerificationKey};
use crate::params::PublicParams;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::Rng;

/// An AirBB signature is of the form σ = (σ₁, σ₂) ∈ G1 × G1 where
///
/// ```text
/// σ₁ = g1^sk · C^r
/// σ₂ = g1^r
/// ```
///
/// with `sk` being the signer's secret key, `r ←$ Fr` a random scalar, and `C = h1^{a·p_M(τ)}` is
/// the set commitment on the full message set M (see `commitment::commit`).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    pub(crate) sigma1: G1Affine,
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Construct a signature from raw group elements (intended for tests).
    pub fn from_parts(sigma1: G1Affine, sigma2: G1Affine) -> Self {
        Self { sigma1, sigma2 }
    }
}

/// Sign a set of messages using a set commitment using `sk`.
///
/// # Signing Protocol
///
/// 1. Sample a scalar `r ←$ Fr`.
/// 2. Compute the set commitment `C = h1^{r·p_M(τ)}` over `messages` (see `commitment::commit`).
/// 3. Output the signature pair:
///    ```text
///    σ₁ = g1^sk · C^r   (in G1)
///    σ₂ = g1^r           (in G1)
///    ```
///
pub fn sign(
    params: &PublicParams,
    sk: &SecretKey,
    messages: &[Fr],
    rng: &mut impl Rng,
) -> Result<Signature, Error> {
    let r = Fr::rand(rng);
    let c = commit(params, messages, &r, CommitGroup::G1)?
        .as_g1()
        .expect("committed with CommitGroup::G1");

    let sigma1 = (G1Projective::from(sk.g1_sk) + c).into_affine();
    let sigma2 = (G1Projective::from(params.g1) * r).into_affine();

    Ok(Signature { sigma1, sigma2 })
}


/// Blind-sign a committed message set, while verifying a revealed subset.
///
/// Expects a commitment pair `com` to the full message set `M` and `com_hid` to the subset of
/// hidden (i.e., non-revealed messages) `M_hid = M \ rev_messages`, along with the revealed
/// messages `rev_messages`.
///   C     = h1^{a · p_M(τ)}      — full commitment     (G1)
///   C_hid = g1^{a · p_hid(τ)}    — hidden commitment   (G1)
///
/// # Protocol
///
/// 1. Recompute the commitment to the revealed messages in G2.
///    ```text
///    C_rev = h2^{p_{M_rev}(τ)}
///    ```
/// 2. Verify the commitment opening via the pairing equation:
///    ```text
///    e(C, g2) == e(C_hid, C_rev)
///    ```
///    Returns `Err(InvalidCommitmentOpeningBlindSign)` if it does not hold.
/// 3. Sample `r ←$ Fr` and output the signature pair:
///    ```text
///    σ₁ = g1^sk · C^r   (in G1)
///    σ₂ = g1^r           (in G1)
///    ```
pub fn blind_sign(
    params: &PublicParams,
    sk: &SecretKey,
    com: &Commitment,
    com_hid: &Commitment,
    rev_messages: &[Fr],
    rng: &mut impl Rng,
) -> Result<Signature, Error> {
    let c = com.as_g1().ok_or(Error::CommitmentWrongGroup {
        exp_group: CommitGroup::G1,
    })?;
    let c_hid = com_hid.as_g1().ok_or(Error::CommitmentWrongGroup {
        exp_group: CommitGroup::G1,
    })?;

    // C_rev = h2^{p_{M_rev}(τ)}
    let c_rev = commit(params, rev_messages, &Fr::one(), CommitGroup::G2)?.as_g2().unwrap();

    // e(C, g2) == e(C_hid, C_rev)
    let lhs: PairingOutput<Bls12_381> = Bls12_381::pairing(c, params.g2);
    let rhs: PairingOutput<Bls12_381> = Bls12_381::pairing(c_hid, c_rev);
    if lhs != rhs {
        return Err(Error::InvalidCommitmentOpeningBlindSign)
    }

    let r = Fr::rand(rng);

    let sigma1 = (G1Projective::from(sk.g1_sk) + c * r).into_affine();
    let sigma2 = (G1Projective::from(params.g1) * r).into_affine();

    Ok(Signature { sigma1, sigma2 })
}

/// Unblind a signature obtained from [`blind_sign`], given the blinding scalar `a`.
///
/// ```text
/// σ₁ = σ₁'
/// σ₂ = (σ₂')^a
/// ```
pub fn unblind(sig: &Signature, a: &Fr) -> Signature {
    Signature {
        sigma1: sig.sigma1,
        sigma2: (G1Projective::from(sig.sigma2) * a).into_affine(),
    }
}

/// Verify a signature (σ₁, σ₂) against `vk` and a message set.
///
///
/// 1. Re-derive the set commitment `C = h2^{a·p_M(τ)}` for the set `messages`.
/// 2. Check the pairing equation:
///    ```text
///    e(σ₁, g2) = vk · e(σ₂, C)
pub fn verify(
    params: &PublicParams,
    vk: &VerificationKey,
    messages: &[Fr],
    sig: &Signature,
) -> Result<bool, Error> {
    if messages.is_empty() {
        return Err(Error::EmptyMessages);
    }

    let c = commit(params, messages, &Fr::one(), CommitGroup::G2)?.as_g2().unwrap();
    let lhs: PairingOutput<Bls12_381> = Bls12_381::pairing(sig.sigma1, params.g2);
    let rhs = PairingOutput::<Bls12_381>(vk.0) +
        Bls12_381::pairing(sig.sigma2, c);


    Ok(lhs == rhs)
}
