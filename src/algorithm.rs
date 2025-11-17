use num_bigint::BigInt;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha512};

static BASE_FIELD_P: Lazy<BigInt> = Lazy::new(|| BigInt::from(2u8).pow(255) - BigInt::from(19u8));

static BASE_FIELD_Q: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from(2u8).pow(252) + BigInt::from(27742317777372353535851937790883648493u128)
});

static MOD_P_SQRT_M1: Lazy<BigInt> = Lazy::new(|| {
    let exponent = (&*BASE_FIELD_P - BigInt::from(1u8)) / BigInt::from(4u8);
    BigInt::from(2u8).modpow(&exponent, &*BASE_FIELD_P)
});

struct Point {
    x: BigInt,
    y: BigInt,
    z: BigInt,
    t: BigInt,
}

pub(crate) struct Ed25519 {}

impl Ed25519 {
    fn sha512(bytes: &[u8]) -> [u8; 64] {
        let mut sha512 = Sha512::new();
        sha512.update(bytes);
        sha512.finalize().into()
    }

    fn mod_p_inverse(x: &BigInt) -> BigInt {
        // p - 2
        let exponent = &*BASE_FIELD_P - BigInt::from(2u8);
        x.modpow(&exponent, &*BASE_FIELD_P)
    }

    // 単位元（Ed25519 の extended coordinates）
    fn identity() -> Point {
        Point {
            x: BigInt::from(0),
            y: BigInt::from(1),
            z: BigInt::from(1),
            t: BigInt::from(0),
        }
    }

    fn get_base_field_d() -> BigInt {
        let x = BigInt::from(121666u32);
        let raw_d = -121665 * Self::mod_p_inverse(&x);
        let p = &*BASE_FIELD_P;
        ((raw_d % p) + p) % p
    }

    fn sha512_mod_q(bytes: &[u8]) -> BigInt {
        let hash_bytes = Self::sha512(bytes);
        let hash_int = BigInt::from_bytes_le(num_bigint::Sign::Plus, &hash_bytes);
        hash_int % &*BASE_FIELD_Q
    }

    fn point_add(p: &Point, q: &Point) -> Point {
        let base_field_d = Self::get_base_field_d();
        let p_x = &p.x;
        let p_y = &p.y;
        let p_z = &p.z;
        let p_t = &p.t;

        let q_x = &q.x;
        let q_y = &q.y;
        let q_z = &q.z;
        let q_t = &q.t;

        let a = (p_y - p_x) * (q_y - q_x) % &*BASE_FIELD_P;
        let b = (p_y + p_x) * (q_y + q_x) % &*BASE_FIELD_P;
        let c = (BigInt::from(2u8) * p_t * q_t * base_field_d) % &*BASE_FIELD_P;
        let d = (BigInt::from(2u8) * p_z * q_z) % &*BASE_FIELD_P;
        let e = (&b - &a) % &*BASE_FIELD_P;
        let f = (&d - &c) % &*BASE_FIELD_P;
        let g = (&d + &c) % &*BASE_FIELD_P;
        let h = (&b + &a) % &*BASE_FIELD_P;

        Point {
            x: (&e * &f) % &*BASE_FIELD_P,
            y: (&g * &h) % &*BASE_FIELD_P,
            z: (&f * &g) % &*BASE_FIELD_P,
            t: (&e * &h) % &*BASE_FIELD_P,
        }
    }

    fn point_multiply(scalar: &BigInt, point: Point) -> Point {
        let mut q = Self::identity();
        let mut addend = point;

        let mut k = scalar.clone();
        while k > BigInt::from(0u8) {
            if &k & BigInt::from(1u8) == BigInt::from(1u8) {
                q = Self::point_add(&q, &addend);
            }
            addend = Self::point_add(&addend, &addend);
            k >>= 1;
        }

        q
    }

    fn point_equal(p: &Point, q: &Point) -> bool {
        let p_x = &p.x;
        let p_y = &p.y;
        let p_z = &p.z;

        let q_x = &q.x;
        let q_y = &q.y;
        let q_z = &q.z;

        if (p_x * q_z - q_x * p_z) % &*BASE_FIELD_P != BigInt::from(0u8) {
            return false;
        }
        if (p_y * q_z - q_y * p_z) % &*BASE_FIELD_P != BigInt::from(0u8) {
            return false;
        }
        true
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_sha512() {
        let input = "abc";

        let actual = Ed25519::sha512(input.as_bytes());

        // 期待される SHA-512("abc") の値
        let expected: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_mod_p_inverse() {
        for i in 1u32..1000 {
            let x = BigInt::from(i);
            let inv_x = Ed25519::mod_p_inverse(&x);
            let product = (&x * &inv_x) % &*BASE_FIELD_P;
            assert_eq!(product, BigInt::from(1u8));
        }
    }

    #[test]
    fn test_get_base_field_d() {
        let d = Ed25519::get_base_field_d();

        // 仕様で決まっている Ed25519 の d
        let expected = BigInt::parse_bytes(
            b"37095705934669439343138083508754565189542113879843219016388785533085940283555",
            10,
        )
        .expect("failed to parse d constant");

        assert_eq!(d, expected);
    }
}
