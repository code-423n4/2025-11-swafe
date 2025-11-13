use ark_ff::Field;

/// Evaluate a polynomial in coefficients form at x
///
/// Most significant coefficient first.
pub fn eval<F: Field, I: Iterator<Item = F>>(coeff: I, x: F) -> F {
    coeff.fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

/// Evaluate the polynomial that vanishes at the given roots at x
pub fn vanish<F: Field, I: Iterator<Item = F>>(roots: I, x: F) -> F {
    roots.fold(F::ONE, |acc, root| acc * (x - root))
}

/// Evaluate the given lagrange polynomial at x
pub fn lagrange<F: Field>(roots: &[F], px: F, x: F) -> F {
    let zero = vanish(roots.iter().cloned(), x);
    let norm = vanish(roots.iter().cloned(), px);
    zero / norm
}

/// Given points (x_i, y_i), compute f(x) where f is the unique polynomial of degree < n
/// that passes through all points
pub fn interpolate_eval<F: Field>(points: &[(F, F)], x: F) -> F {
    assert!(!points.is_empty(), "must have at least one point");
    let xs = points.iter().map(|&(px, _)| px).collect::<Vec<_>>();
    points.iter().fold(F::ZERO, |eval, &(px, py)| {
        let roots: Vec<F> = xs.iter().cloned().filter(|&x| x != px).collect();
        eval + py * lagrange(&roots, px, x)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    #[test]
    fn test_vanish_poly_empty_roots() {
        let x = Fr::from(5u64);
        let result = vanish([].into_iter(), x);
        assert_eq!(result, Fr::one());
    }

    #[test]
    fn test_vanish_poly_single_root() {
        let x = Fr::from(5u64);
        let result = vanish([Fr::from(3u64)].into_iter(), x);
        assert_eq!(result, Fr::from(2u64));
    }

    #[test]
    fn test_vanish_poly_multiple_roots() {
        let x = Fr::from(5u64);
        let result = vanish(
            [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)].into_iter(),
            x,
        );
        assert_eq!(result, Fr::from(24u64));
    }

    #[test]
    fn test_vanish_poly_at_root() {
        let x = Fr::from(2u64);
        let result = vanish(
            [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)].into_iter(),
            x,
        );
        assert_eq!(result, Fr::zero());
    }

    #[test]
    fn test_lagrange_interpolate_and_eval_single_point() {
        let points = vec![(Fr::from(1u64), Fr::from(5u64))];
        let x = Fr::from(2u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(5u64));
    }

    #[test]
    fn test_lagrange_interpolate_and_eval_linear() {
        let points = vec![
            (Fr::from(1u64), Fr::from(2u64)),
            (Fr::from(2u64), Fr::from(4u64)),
        ];
        let x = Fr::from(3u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(6u64));
    }

    #[test]
    fn test_lagrange_interpolate_and_eval_quadratic() {
        let points = vec![
            (Fr::from(1u64), Fr::from(1u64)),
            (Fr::from(2u64), Fr::from(4u64)),
            (Fr::from(3u64), Fr::from(9u64)),
        ];
        let x = Fr::from(4u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(16u64));
    }

    #[test]
    fn test_lagrange_interpolate_and_eval_at_known_point() {
        let points = vec![
            (Fr::from(1u64), Fr::from(10u64)),
            (Fr::from(2u64), Fr::from(20u64)),
            (Fr::from(3u64), Fr::from(30u64)),
        ];
        let x = Fr::from(2u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(20u64));
    }

    #[test]
    fn test_lagrange_interpolate_and_eval_zero() {
        let points = vec![
            (Fr::from(1u64), Fr::from(3u64)),
            (Fr::from(2u64), Fr::from(5u64)),
            (Fr::from(3u64), Fr::from(7u64)),
        ];
        let x = Fr::zero();
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(1u64));
    }

    #[test]
    fn test_lagrange_interpolate_with_negative_values() {
        let points = vec![
            (-Fr::from(1u64), Fr::from(1u64)),
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(1u64), Fr::from(1u64)),
        ];
        let x = Fr::from(2u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(4u64));
    }

    #[test]
    fn test_constant_polynomial() {
        let points = vec![
            (Fr::from(1u64), Fr::from(7u64)),
            (Fr::from(2u64), Fr::from(7u64)),
            (Fr::from(3u64), Fr::from(7u64)),
        ];
        let x = Fr::from(100u64);
        let result = interpolate_eval(&points, x);
        assert_eq!(result, Fr::from(7u64));
    }
}
