use crate::crypto::pairing as pp;

// Note: The book mentions secp256r1, but we use BLS12-381 throughout
// for consistency with the VDRF implementation which requires pairing-friendly curves.
// This is a design choice to unify the cryptographic primitives.
pub type Fr = pp::Fr;
pub type GAffine = pp::G1Affine;
pub type GProjective = pp::G1Projective;

// Serialization modules for pairing group elements
pub(crate) mod serialize {
    // serialization for individual elements
    use super::*;
    pub(crate) use pp::serialize::{fr, g1 as g};
}
