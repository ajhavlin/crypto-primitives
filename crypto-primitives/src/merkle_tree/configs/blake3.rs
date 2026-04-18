use crate::crh::blake3::{Blake3CRH, Blake3TwoToOneCRH};
use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::merkle_tree::{Config, IdentityDigestConverter};
use ark_ff::Field;
use ark_std::marker::PhantomData;

/// Merkle tree configuration using Blake3.
#[derive(Clone)]
pub struct Blake3MerkleConfig<F: Field> {
    _field: PhantomData<F>,
}

impl<F: Field> Config for Blake3MerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = Blake3CRH<F>;
    type TwoToOneHash = Blake3TwoToOneCRH;
}
