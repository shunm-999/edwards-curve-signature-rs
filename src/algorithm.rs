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

    fn recover_x(y: &BigInt, sign: &BigInt) -> Option<BigInt> {
        let p = &*BASE_FIELD_P;
        let one = BigInt::from(1u8);

        // 0 <= y < p でなければダメ
        if y >= p {
            return None;
        }

        let y2 = (y * y) % p;

        // x^2 = (y^2 - 1) / (1 + d y^2)
        let num = (y2.clone() - &one + p) % p;
        let den = (Self::get_base_field_d() * &y2 + &one) % p;
        let den_inv = Self::mod_p_inverse(&den);
        let x2 = (num * den_inv) % p;

        if x2 == BigInt::from(0u8) {
            // x = 0 のときは sign が 0 なら OK, 1 なら reject
            return if *sign == BigInt::from(0u8) {
                Some(BigInt::from(0u8))
            } else {
                None
            };
        }

        // sqrt: x = x2^((p+3)/8)
        let exp = (p.clone() + BigInt::from(3u8)) >> 3;
        let mut x = x2.modpow(&exp, p);

        // チェック (1回目)
        let mut check = (&x * &x) % p;
        if check != x2 {
            // もう一回、sqrt(-1) を掛けてみる
            x = (&x * &*MOD_P_SQRT_M1) % p;
            check = (&x * &x) % p;
            if check != x2 {
                return None;
            }
        }

        // 符号ビットに合わせる
        if (&x & BigInt::from(1u8)) != (sign & BigInt::from(1u8)) {
            x = p - &x;
        }

        Some(x)
    }

    fn point_compress(p: &Point) -> Vec<u8> {
        let z_inverse = Self::mod_p_inverse(&p.z);

        let x = (&p.x * &z_inverse) % &*BASE_FIELD_P;
        let y = (&p.y * &z_inverse) % &*BASE_FIELD_P;

        let x_sign = &x & BigInt::from(1u8);
        (&y | &(x_sign.clone() << 255)).to_bytes_le().1
    }

    fn point_decompress(mut bytes: Vec<u8>) -> Option<Point> {
        if bytes.len() != 32 {
            return None;
        }

        let sign = bytes[31] >> 7;
        bytes[31] &= 0x7F; // 最上位ビットをクリア

        let y = BigInt::from_bytes_le(num_bigint::Sign::Plus, &bytes);

        let x = Self::recover_x(&y, &BigInt::from(sign));
        if x.is_none() {
            return None;
        }
        let x = x.unwrap();

        let z = BigInt::from(1u8);
        let t = (&x * &y) % &*BASE_FIELD_P;

        Some(Point { x, y, z, t })
    }

    fn secret_expand(secret: &[u8]) -> Option<(BigInt, [u8; 32])> {
        if secret.len() != 32 {
            return None;
        }

        let h = Self::sha512(secret);

        let mut a = BigInt::from_bytes_le(num_bigint::Sign::Plus, &h[0..32]);

        // clamp: a &= (1 << 254) - 8;
        a &= (BigInt::from(1u8) << 254) - 8;
        // clamp: a |= 1 << 254;
        a |= BigInt::from(1u8) << 254;

        // 後ろ 32 バイトを prefix として返す
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);

        Some((a, prefix))
    }
}

mod tests {
    use super::*;
    use num_bigint::BigInt;

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

    #[test]
    fn test_recover_x_rejects_invalid_y_ge_p() {
        // y >= p は不正入力として None を返す
        let p = &*BASE_FIELD_P;
        let y = p.clone(); // y == p は NG
        let sign = BigInt::from(0u8);

        let x = Ed25519::recover_x(&y, &sign);
        assert!(x.is_none());
    }

    #[test]
    fn test_recover_x_identity_point_x_0_y_1() {
        // 単位元 (x, y) = (0, 1) のテスト
        // 符号ビット 0 -> x = 0 が返ってくる
        // 符号ビット 1 -> 非正規形として None
        let y = BigInt::from(1u8);

        let sign0 = BigInt::from(0u8);
        let x0 = Ed25519::recover_x(&y, &sign0);
        assert_eq!(x0, Some(BigInt::from(0u8)));

        let sign1 = BigInt::from(1u8);
        let x1 = Ed25519::recover_x(&y, &sign1);
        assert!(x1.is_none());
    }

    #[test]
    fn test_recover_x_basepoint() {
        // Ed25519 のベースポイント B の座標
        // Bx, By は仕様で決まっている定数
        // B = (1511222..., 4631683... )
        let y = BigInt::parse_bytes(
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960",
            10,
        )
        .unwrap();
        let x_expected = BigInt::parse_bytes(
            b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
            10,
        )
        .unwrap();

        // 公開鍵エンコード時と同じく、sign は x の LSB（最下位ビット）
        let sign = &x_expected & BigInt::from(1u8);

        let x =
            Ed25519::recover_x(&y, &sign).expect("base point should be recoverable from (y, sign)");

        assert_eq!(x, x_expected);
    }

    #[test]
    fn test_secret_expand_invalid_length() {
        // 長さが 32 バイト以外なら None を返す
        let short = [0u8; 31];
        let long = [0u8; 33];

        assert!(Ed25519::secret_expand(&short).is_none());
        assert!(Ed25519::secret_expand(&long).is_none());
    }

    #[test]
    fn test_secret_expand_zero_seed() {
        // seed = 0x00..00（32 バイト）のときの期待値
        let seed = [0u8; 32];
        let (a, prefix) = Ed25519::secret_expand(&seed)
            .expect("secret_expand should return Some for 32-byte seed");

        // 事前に仕様通りに計算した clamped a の値（10 進）
        let expected_a = BigInt::parse_bytes(
            b"39325648866980652792715009169219496062012184734522019333892538943312776480336",
            10,
        )
        .expect("failed to parse expected a for zero seed");

        assert_eq!(a, expected_a);

        let expected_prefix: [u8; 32] = [
            0x0a, 0x6a, 0x85, 0xea, 0xa6, 0x42, 0xda, 0xc8,
            0x35, 0x42, 0x4b, 0x5d, 0x7c, 0x8d, 0x63, 0x7c,
            0x00, 0x40, 0x8c, 0x7a, 0x73, 0xda, 0x67, 0x2b,
            0x7f, 0x49, 0x85, 0x21, 0x42, 0x0b, 0x6d, 0xd3,
        ];

        assert_eq!(prefix, expected_prefix);
    }

    #[test]
    fn test_secret_expand_incrementing_seed() {
        // seed = 0x00,0x01,...,0x1f のときの期待値
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }

        let (a, prefix) = Ed25519::secret_expand(&seed)
            .expect("secret_expand should return Some for 32-byte seed");

        let expected_a = BigInt::parse_bytes(
            b"50459379271018302582465998844449622265826330103819895252966304478993432089656",
            10,
        )
        .expect("failed to parse expected a for incrementing seed");

        assert_eq!(a, expected_a);

        let expected_prefix: [u8; 32] = [
            0xa9, 0xd7, 0x18, 0x62, 0xa3, 0xe5, 0x74, 0x6b,
            0x57, 0x1b, 0xe3, 0xd1, 0x87, 0xb0, 0x04, 0x10,
            0x46, 0xf5, 0x2e, 0xbd, 0x85, 0x0c, 0x7c, 0xbd,
            0x5f, 0xde, 0x8e, 0xe3, 0x84, 0x73, 0xb6, 0x49,
        ];

        assert_eq!(prefix, expected_prefix);
    }
}
