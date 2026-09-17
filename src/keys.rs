use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::PublicParams;

/// Secret key: a random scalar `sk` and `g1^sk` used for signing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    sk: Fr,
    pub(crate) g1_sk: G1Affine,
}

/// A t-out-of-n Shamir share of a secret key, held by issuer `index` (1-based).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    pub index: usize,
    pub(crate) sk_i: Fr,
    pub(crate) g1_sk_i: G1Affine,
}

impl SecretKey {
    pub fn random(params: &PublicParams, rng: &mut impl Rng) -> Self {
        let sk = Fr::rand(rng);
        let g1_sk = (G1Projective::from(params.g1) * sk).into_affine();
        Self { sk, g1_sk }
    }
}

/// Verification key: `vk = e(g1, g2)^sk = g_t^sk`.
///
/// Computed using a pairing as `e(sk·g1, g2)`.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerificationKey(pub(crate) <Bls12_381 as Pairing>::TargetField);

impl VerificationKey {
    pub fn is_identity(&self) -> bool {
        use ark_ff::One;
        self.0.is_one()
    }

    pub fn from_secret(params: &PublicParams, sk: &SecretKey) -> Self {
        // e(g1, g2)^sk = e(sk * g1, g2)  by bilinearity
        let sk_g1 = (G1Projective::from(params.g1) * sk.sk).into_affine();
        let gt = Bls12_381::pairing(sk_g1, params.g2);
        Self(gt.0)
    }
}

/// Sample a new secret- and verification key.
pub fn keygen(params: &PublicParams, rng: &mut impl Rng) -> (SecretKey, VerificationKey) {
    let sk = SecretKey::random(params, rng);
    let vk = VerificationKey::from_secret(params, &sk);
    (sk, vk)
}

/// Shamir-share `sk` into `n` shares with threshold `t` (1 <= t <= n).
/// Returns shares indexed 1..=n.
pub fn shamir_share(sk: &Fr, n: usize, t: usize, rng: &mut impl Rng) -> Vec<KeyShare> {
    assert!(n > 0 && t > 0 && t <= n, "threshold must satisfy 1 <= t <= n");

    let mut coefficients = Vec::with_capacity(t);
    coefficients.push(*sk);
    coefficients.extend((1..t).map(|_| Fr::rand(rng)));

    (1..=n)
        .map(|index| {
            let x = Fr::from(index as u64);
            let sk_i = coefficients
                .iter()
                .rev()
                .fold(Fr::from(0u64), |value, coefficient| value * x + *coefficient);

            let g1_sk_i = (G1Projective::generator() * sk_i).into_affine();

            KeyShare {
                index,
                sk_i,
                g1_sk_i,
            }
        })
        .collect()
}

/// Sample a secret key, Shamir-share it, and return the shares and verification key.
pub fn threshold_keygen(
    params: &PublicParams,
    n: usize,
    t: usize,
    rng: &mut impl Rng,
) -> (Vec<KeyShare>, VerificationKey) {
    let sk = SecretKey::random(params, rng);
    let vk = VerificationKey::from_secret(params, &sk);
    let shares = shamir_share(&sk.sk, n, t, rng);
    (shares, vk)
}

/// Lagrange coefficient for index `i` evaluated at x = 0.
pub fn lagrange_coefficient(indices: &[usize], i: usize) -> Fr {
    assert!(i > 0, "index must starting from 1");
    assert!(indices.contains(&i), "index must be among the participating shares");
    assert!(
        indices.iter().all(|&index| index > 0)
            && indices.iter().enumerate().all(|(position, index)| {
                !indices[..position].contains(index)
            }),
        "participating indices must be unique"
    );

    let x_i = Fr::from(i as u64);
    let (numerator, denominator) = indices
        .iter()
        .copied()
        .filter(|&j| j != i)
        .fold((Fr::from(1u64), Fr::from(1u64)), |(numerator, denominator), j| {
            let x_j = Fr::from(j as u64);
            (numerator * x_j, denominator * (x_j - x_i))
        });
    numerator * denominator.inverse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_shares_reconstruct_secret() {
        let mut rng = ark_std::test_rng();
        let params = PublicParams::setup(3, &mut rng);
        let secret = SecretKey::random(&params, &mut rng);
        let shares = shamir_share(&secret.sk, 5, 3, &mut rng);
        let selected = &shares[..3];
        let indices: Vec<usize> = selected.iter().map(|share| share.index).collect();
        let reconstructed = selected.iter().fold(Fr::from(0u64), |value, share| {
            value + share.sk_i * lagrange_coefficient(&indices, share.index)
        });

        assert_eq!(reconstructed, secret.sk);
    }
}
