use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::Borrow, rand::Rng};
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

use crate::{
    crh::{ByteDigest, CRHScheme, TwoToOneCRHScheme},
    Error,
};

// Blake3 CRH over field elements.
// Serializes field elements to bytes and hashes them resulting in a 32 byte digest.
#[derive(Clone)]
pub struct Blake3CRH<F: Field> {
    _f: PhantomData<F>,
}

impl<F: Field> CRHScheme for Blake3CRH<F> {
    type Input = [F];
    type Output = ByteDigest<32>;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut buf = Vec::new();
        input.borrow().serialize_compressed(&mut buf)?;
        Ok(ByteDigest(*blake3::hash(&buf).as_bytes()))
    }
}

// Blake3 two-to-one CRH for internal Merkle tree nodes.
// Hashes `left || right` using BLAKE3, producing a 32-byte digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3TwoToOneCRH;

impl TwoToOneCRHScheme for Blake3TwoToOneCRH {
    type Input = ByteDigest<32>;
    type Output = ByteDigest<32>;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&left_input.borrow().0);
        hasher.update(&right_input.borrow().0);
        Ok(ByteDigest(*hasher.finalize().as_bytes()))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    type F = ark_ed_on_bls12_381::Fr;

    #[test]
    fn blake3_crh_deterministic() {
        let params = Blake3CRH::<F>::setup(&mut test_rng()).unwrap();
        let input = vec![F::from(42u64), F::from(99u64)];

        let h1 = Blake3CRH::<F>::evaluate(&params, input.as_slice()).unwrap();
        let h2 = Blake3CRH::<F>::evaluate(&params, input.as_slice()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_crh_different_inputs() {
        let params = Blake3CRH::<F>::setup(&mut test_rng()).unwrap();
        let a = vec![F::from(1u64)];
        let b = vec![F::from(2u64)];

        let ha = Blake3CRH::<F>::evaluate(&params, a.as_slice()).unwrap();
        let hb = Blake3CRH::<F>::evaluate(&params, b.as_slice()).unwrap();
        assert_ne!(ha, hb);
    }

    #[test]
    fn blake3_two_to_one_deterministic() {
        let params = Blake3TwoToOneCRH::setup(&mut test_rng()).unwrap();
        let left = ByteDigest([1u8; 32]);
        let right = ByteDigest([2u8; 32]);

        let h1 = Blake3TwoToOneCRH::evaluate(&params, &left, &right).unwrap();
        let h2 = Blake3TwoToOneCRH::evaluate(&params, &left, &right).unwrap();
        assert_eq!(h1, h2);

        let h3 = Blake3TwoToOneCRH::evaluate(&params, &right, &left).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn blake3_compress_matches_evaluate() {
        let params = Blake3TwoToOneCRH::setup(&mut test_rng()).unwrap();
        let left = ByteDigest([0xAA; 32]);
        let right = ByteDigest([0xBB; 32]);

        let eval = Blake3TwoToOneCRH::evaluate(&params, &left, &right).unwrap();
        let comp = Blake3TwoToOneCRH::compress(&params, &left, &right).unwrap();
        assert_eq!(eval, comp);
    }
}
