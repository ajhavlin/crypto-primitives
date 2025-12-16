use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use crate::merkle_tree::{
    decode_delta, decode_varint, encode_delta, encode_varint, CoPath, Config, DefaultHasher,
    IdentityDigestConverter,
};
use ark_std::{borrow::Borrow, collections::BTreeMap, hash::BuildHasherDefault};
use hashbrown::HashMap;

struct DummyCfg;
impl Config for DummyCfg {
    type Leaf = ();
    type LeafDigest = u8;
    type LeafInnerDigestConverter = IdentityDigestConverter<u8>;
    type InnerDigest = u8;
    type LeafHash = DummyLeafHash;
    type TwoToOneHash = DummyTwoToOne;
}

struct DummyLeafHash;
impl CRHScheme for DummyLeafHash {
    type Input = ();
    type Output = u8;
    type Parameters = ();

    fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, crate::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        _input: T,
    ) -> Result<Self::Output, crate::Error> {
        Ok(0)
    }
}

struct DummyTwoToOne;
impl TwoToOneCRHScheme for DummyTwoToOne {
    type Input = u8;
    type Output = u8;
    type Parameters = ();

    fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, crate::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, crate::Error> {
        Ok(*left.borrow() ^ *right.borrow())
    }

    fn compress<T: Borrow<Self::Output>>(
        _parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, crate::Error> {
        Ok(*left.borrow() ^ *right.borrow())
    }
}

#[test]
fn varint_roundtrips() {
    let samples = [
        0u64,
        1,
        2,
        42,
        127,
        128,
        255,
        256,
        10_000,
        u32::MAX as u64,
        u64::MAX / 2,
    ];

    for &value in &samples {
        let mut buf = Vec::new();
        encode_varint(&mut buf, value);
        let mut cursor = 0usize;
        let decoded = decode_varint(&buf, &mut cursor).expect("must decode");
        assert_eq!(decoded, value);
        assert_eq!(cursor, buf.len(), "cursor should advance to end");
    }
}

#[test]
fn delta_roundtrips() {
    let samples = [
        0i64,
        1,
        -1,
        5,
        -7,
        127,
        -128,
        256,
        -256,
        i32::MAX as i64,
        i32::MIN as i64,
    ];

    for &value in &samples {
        let mut buf = Vec::new();
        encode_delta(&mut buf, value);
        let mut cursor = 0usize;
        let decoded = decode_delta(&buf, &mut cursor).expect("must decode");
        assert_eq!(decoded, value);
        assert_eq!(cursor, buf.len(), "cursor should advance to end");
    }
}

#[test]
fn decode_rejects_tampered_deltas() {
    let entries: Vec<(usize, usize, u8)> = vec![(1, 0, 10), (1, 1, 20), (2, 2, 30)];
    let packed = CoPath::<DummyCfg>::pack_inner_copath(&entries).expect("packs");

    // Tamper with deltas: flip a bit.
    let mut tampered = packed.clone();
    tampered.2[0] ^= 0b0000_0001;

    let mut inner_levels: Vec<BTreeMap<usize, u8>> = (0..4).map(|_| BTreeMap::new()).collect();
    let mut lut = HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());
    let ok =
        CoPath::<DummyCfg>::decode_inner_copath(4, &Some(tampered), &mut inner_levels, &mut lut);
    assert!(!ok, "tampered deltas should be rejected");
}

#[test]
fn pack_decode_roundtrip_preserves_entries() {
    let entries: Vec<(usize, usize, u8)> = vec![(1, 0, 10), (1, 1, 20), (2, 2, 30)];
    let packed = CoPath::<DummyCfg>::pack_inner_copath(&entries).expect("packs");

    let mut inner_levels: Vec<BTreeMap<usize, u8>> = (0..4).map(|_| BTreeMap::new()).collect();
    let mut lut = HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());
    let ok = CoPath::<DummyCfg>::decode_inner_copath(4, &Some(packed), &mut inner_levels, &mut lut);
    assert!(ok, "packed/decoded should succeed");

    for &(depth, idx, ref digest) in &entries {
        assert_eq!(
            inner_levels[depth].get(&idx),
            Some(digest),
            "entry at depth {}, idx {} should roundtrip",
            depth,
            idx
        );
    }
}
