use ark_ff::AdditiveGroup;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{pairing as pp, poly},
    Tagged,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct Share(#[serde(with = "crate::crypto::pairing::serialize::fr")] pp::Fr);

impl Tagged for Share {
    const SEPARATOR: &'static str = "v0:sss-share";
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct Secret(#[serde(with = "crate::crypto::pairing::serialize::fr")] pp::Fr);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret").finish_non_exhaustive()
    }
}

impl Tagged for Secret {
    const SEPARATOR: &'static str = "v0:sss-secret";
}

/// Generate a Shamir secret sharing
pub(crate) fn share<R: RngCore + CryptoRng>(
    rng: &mut R,
    t: usize,
    n: usize,
) -> (Secret, Vec<Share>) {
    // a threshold 0 sharing is just a constant
    if t == 0 {
        return (Secret(pp::Fr::ZERO), vec![]);
    }

    // for thresholds greater than 0, define a degree t-1 polynomial
    let cs: Vec<pp::Fr> = (0..t).map(|_| rng.gen()).collect();
    let ss = (1..=n)
        .map(|i| Share(poly::eval(cs.iter().cloned().rev(), pp::Fr::from(i as u64))))
        .collect();
    (Secret(cs[0]), ss)
}

/// Recover a secret from a qualified set of shares
pub(crate) fn recover(shares: &[(usize, Share)]) -> Secret {
    // a threshold of 0 is just a constant
    if shares.is_empty() {
        return Secret(pp::Fr::ZERO);
    }

    // for higher thresholds we interpolate the polynomial
    let points: Vec<(pp::Fr, pp::Fr)> = shares
        .iter()
        .map(|(i, share)| (pp::Fr::from(i.saturating_add(1) as u64), share.0))
        .collect();
    Secret(poly::interpolate_eval(&points, pp::Fr::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_share_and_recover_basic() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 3, 5);

        // Test recovery with exactly threshold shares
        let qualified_shares: Vec<(usize, Share)> =
            shares.into_iter().take(3).enumerate().collect();

        assert_eq!(secret, recover(&qualified_shares));
    }

    #[test]
    fn test_share_and_recover_with_more_than_threshold() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 2, 5);

        // Test recovery with more than threshold shares
        let qualified_shares: Vec<(usize, Share)> =
            shares.into_iter().take(4).enumerate().collect();

        assert_eq!(secret, recover(&qualified_shares));
    }

    #[test]
    fn test_share_and_recover_different_subsets() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 3, 6);

        // Test recovery with different subsets of shares
        let subset1: Vec<(usize, Share)> = vec![
            (0, shares[0].clone()),
            (1, shares[1].clone()),
            (2, shares[2].clone()),
        ];

        let subset2: Vec<(usize, Share)> = vec![
            (1, shares[1].clone()),
            (3, shares[3].clone()),
            (5, shares[5].clone()),
        ];

        let recovered1 = recover(&subset1);
        let recovered2 = recover(&subset2);

        assert_eq!(secret, recovered1);
        assert_eq!(secret, recovered2);
        assert_eq!(recovered1, recovered2);
    }

    #[test]
    fn test_threshold_one() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 1, 3);

        // With threshold 1, any single share should recover the secret
        for (i, share) in shares.iter().enumerate().take(3) {
            let single_share = vec![(i, share.clone())];
            let recovered = recover(&single_share);
            assert_eq!(secret, recovered);
        }
    }

    #[test]
    fn test_threshold_zero() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 0, 5);

        // With threshold 0, secret should be zero and no shares generated
        assert_eq!(secret, Secret(pp::Fr::ZERO));
        assert!(shares.is_empty());

        // Recovery with empty shares should return zero
        let recovered = recover(&[]);
        assert_eq!(recovered, Secret(pp::Fr::ZERO));
    }

    #[test]
    fn test_insufficient_shares() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 3, 5);

        // Test with fewer than threshold shares (should not recover correctly)
        let insufficient_shares: Vec<(usize, Share)> =
            shares.into_iter().take(2).enumerate().collect();

        // With insufficient shares, recovery should not match original secret
        assert!(secret != recover(&insufficient_shares));
    }

    #[test]
    fn test_large_threshold() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 10, 15);

        // Test with exactly threshold shares
        let qualified_shares: Vec<(usize, Share)> =
            shares.into_iter().take(10).enumerate().collect();

        assert_eq!(secret, recover(&qualified_shares));
    }

    #[test]
    fn test_all_shares_recovery() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 4, 7);

        // Test recovery with all shares
        let all_shares: Vec<(usize, Share)> = shares.into_iter().enumerate().collect();

        assert!(secret == recover(&all_shares));
    }

    #[test]
    fn test_non_consecutive_indices() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 3, 10);

        // Test with non-consecutive indices
        let non_consecutive: Vec<(usize, Share)> = vec![
            (1, shares[1].clone()),
            (4, shares[4].clone()),
            (8, shares[8].clone()),
        ];
        assert!(secret == recover(&non_consecutive));
    }

    #[test]
    fn test_threshold_equals_total_shares() {
        let mut rng = thread_rng();
        let (secret, shares) = share(&mut rng, 5, 5);

        // When threshold equals total shares, need all shares to recover
        let all_shares: Vec<(usize, Share)> = shares.into_iter().enumerate().collect();
        assert!(secret == recover(&all_shares));
    }
}
