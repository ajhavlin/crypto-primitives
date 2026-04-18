use crate::crh::poseidon::{CRH as PoseidonCRH, TwoToOneCRH as PoseidonTwoToOneCRH};
use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::merkle_tree::{Config, IdentityDigestConverter};
use crate::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

/// Merkle tree configuration using Poseidon.
#[derive(Clone)]
pub struct PoseidonMerkleConfig<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for PoseidonMerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = PoseidonCRH<F>;
    type TwoToOneHash = PoseidonTwoToOneCRH<F>;
}
