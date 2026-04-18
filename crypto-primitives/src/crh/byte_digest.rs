use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::Absorb,
    Error,
};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, marker::PhantomData, rand::Rng};
use digest::Digest;

/// Fixed-size byte digest.
#[derive(Clone, Debug, Eq, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ByteDigest<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for ByteDigest<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> AsRef<[u8]> for ByteDigest<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for ByteDigest<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Absorb for ByteDigest<N> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.0);
    }

    fn to_sponge_field_elements<F: ark_ff::PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from_be_bytes_mod_order(&self.0));
    }
}

/// Domain tag for the two leaf hashes that form the bottom non-leaf layer.
pub const LEAF_PAIR_TAG: &[u8] = b"ark-mt:v1:leaf-pair";
/// Domain tag for two inner-node hashes.
pub const INNER_TAG: &[u8] = b"ark-mt:v1:inner";

/// Hash `tag || left_input || right_input` with `D`.
pub fn digest_pair<D: Digest>(tag: &[u8], left_input: &[u8], right_input: &[u8]) -> Vec<u8> {
    let mut h = D::new();
    h.update(tag);
    h.update(left_input);
    h.update(right_input);

    let output = h.finalize();
    output.to_vec()
}

/// A byte-oriented CRH wrapper for RustCrypto `Digest` implementations.
///
/// The one-input CRH remains the raw digest `D(input)`. The two-to-one CRH is
/// domain separated for Merkle trees by hashing a node-kind tag before the
/// child inputs.
pub struct MerkleByteDigest<D: Digest> {
    digest: PhantomData<D>,
}

impl<D: Digest> CRHScheme for MerkleByteDigest<D> {
    type Input = [u8];
    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let output = D::digest(input.borrow());
        Ok(output.to_vec())
    }
}

impl<D: Digest> TwoToOneCRHScheme for MerkleByteDigest<D> {
    type Input = [u8];
    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Ok(digest_pair::<D>(
            LEAF_PAIR_TAG,
            left_input.borrow(),
            right_input.borrow(),
        ))
    }

    fn compress<T: Borrow<Self::Output>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Ok(digest_pair::<D>(
            INNER_TAG,
            left_input.borrow().as_slice(),
            right_input.borrow().as_slice(),
        ))
    }
}
