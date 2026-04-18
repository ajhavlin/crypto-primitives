use crate::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*, uint8::UInt8};
use ark_relations::gr1cs::SynthesisError;
use ark_std::fmt::Debug;

pub trait CRHSchemeGadget<H: CRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + GR1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}

pub trait TwoToOneCRHSchemeGadget<H: TwoToOneCRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + GR1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}

/// Gadget form of [`crate::crh::ByteTwoToOneCRHScheme`]: inputs are byte variables,
/// output is a witness-native digest convertible to bytes.
pub trait ByteTwoToOneCRHSchemeGadget<ConstraintF: PrimeField>: Sized {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + GR1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[UInt8<ConstraintF>],
        right_input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &[UInt8<ConstraintF>],
        right_input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}

/// Gadget form of [`crate::crh::FieldTwoToOneCRHScheme`]: inputs and outputs are
/// field-element variables over `F`.
pub trait FieldTwoToOneCRHSchemeGadget<F: PrimeField>: Sized {
    type ParametersVar: Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &FpVar<F>,
        right_input: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError>;

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &FpVar<F>,
        right_input: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError>;
}
