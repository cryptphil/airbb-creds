use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::Rng;


/// Public parameters for the signature scheme.
///
/// Generated once for a maximum message count `l`. Contains group generators
/// used in both key derivation and signing.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams {
    /// Maximum number of messages that can be signed.
    pub l: usize,
    /// Base generator in G1.
    pub g1: G1Affine,
    /// Base generator in G2.
    pub g2: G2Affine,
    /// H generator in G1.
    pub h1: G1Affine,
    /// H generator in G2.
    pub h2: G2Affine,

    /// Powers-of-tau for secret τ.
    /// `[g1^τ, g1^{τ²}, ..., g1^{τ^{l+1}}]`
    pub g1_tau: Vec<G1Affine>,
    /// `[h2^τ, h2^{τ²}, ..., h2^{τ^l}]`
    pub h2_tau: Vec<G2Affine>,
    /// `[h1^τ, h1^{τ²}, ..., h1^{τ^l}]`
    pub h1_tau: Vec<G1Affine>
}

impl PublicParams {
    /// Set up the structured reference string for up to `l` messages.
    pub fn setup(l: usize, rng: &mut impl Rng) -> Self {
        assert!(l > 0, "l must be at least 1");

        let g1: G1Affine = G1Projective::generator().into_affine();
        let g2: G2Affine = G2Projective::generator().into_affine();

        let hx: Fr = Fr::rand(rng);
        let h1: G1Affine = (G1Projective::from(g1) * hx).into_affine();
        let h2: G2Affine = (G2Projective::from(g2) * hx).into_affine();

        // Sample secret τ
        let tau: Fr = Fr::rand(rng);
        let mut g1_tau =  Vec::<G1Affine>::with_capacity(l + 1);
        let mut h1_tau =  Vec::<G1Affine>::with_capacity(l);
        let mut h2_tau =  Vec::<G2Affine>::with_capacity(l);

        for i in 1u64..= l as u64 {
            let tau_pow = tau.pow([i]);
            g1_tau.push((G1Projective::from(g1) * tau_pow).into_affine());
            h1_tau.push((G1Projective::from(h1) * tau_pow).into_affine());
            h2_tau.push((G2Projective::from(h2) * tau_pow).into_affine());
        }
        // g1_tau needs one extra power (τ^{l+1}).
        g1_tau.push((G1Projective::from(g1) * tau.pow([l as u64 + 1])).into_affine());

        Self {
            l,
            g1,
            g2,
            h1,
            h2,
            g1_tau,
            h1_tau,
            h2_tau
        }
    }
}
