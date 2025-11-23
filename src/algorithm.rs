use num_bigint::BigUint;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha512};

static BASE_FIELD_P: Lazy<BigUint> =
    Lazy::new(|| BigUint::from(2u8).pow(255) - BigUint::from(19u8));

static BASE_FIELD_Q: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from(2u8).pow(252) + BigUint::from(27742317777372353535851937790883648493u128)
});

static MOD_P_SQRT_M1: Lazy<BigUint> = Lazy::new(|| {
    // sqrt(-1) mod p = 2^((p-1)/4) mod p
    let exponent = (&*BASE_FIELD_P - BigUint::from(1u8)) / BigUint::from(4u8);
    BigUint::from(2u8).modpow(&exponent, &*BASE_FIELD_P)
});

#[derive(Clone, Debug)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

pub(crate) struct Ed25519 {}

impl Ed25519 {
    fn sha512(bytes: &[u8]) -> [u8; 64] {
        let mut sha512 = Sha512::new();
        sha512.update(bytes);
        sha512.finalize().into()
    }

    /// a^-1 mod p
    fn mod_p_inverse(x: &BigUint) -> BigUint {
        // exponent = p - 2
        let exponent = &*BASE_FIELD_P - BigUint::from(2u8);
        x.modpow(&exponent, &*BASE_FIELD_P)
    }

    fn add_mod(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        (a + b) % p
    }

    fn sub_mod(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        if a >= b { (a - b) % p } else { (a + p - b) % p }
    }

    fn mul_mod(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        (a * b) % p
    }

    // 単位元（Ed25519 の extended coordinates）
    fn identity() -> Point {
        Point {
            x: BigUint::from(0u8),
            y: BigUint::from(1u8),
            z: BigUint::from(1u8),
            t: BigUint::from(0u8),
        }
    }

    fn get_base_field_d() -> BigUint {
        // d = -121665 / 121666 mod p
        let p = &*BASE_FIELD_P;
        let num = Self::sub_mod(&p, &BigUint::from(121665u32), &p); // -121665 ≡ p - 121665 (mod p)
        let den = BigUint::from(121666u32);
        let den_inv = Self::mod_p_inverse(&den);
        Self::mul_mod(&num, &den_inv, p)
    }

    fn get_base_point() -> Point {
        let p = &*BASE_FIELD_P;

        // By = 4/5 mod p
        let four = BigUint::from(4u8);
        let five = BigUint::from(5u8);
        let inv_five = Self::mod_p_inverse(&five);
        let y = Self::mul_mod(&four, &inv_five, p);

        // Bx は recover_x で求める
        let x =
            Self::recover_x(&y, &BigUint::from(0u8)).expect("failed to recover x for base point");

        let z = BigUint::from(1u8);
        let t = Self::mul_mod(&x, &y, p);
        Point { x, y, z, t }
    }

    fn sha512_mod_q(bytes: &[u8]) -> BigUint {
        let hash_bytes = Self::sha512(bytes);
        let hash_int = BigUint::from_bytes_le(&hash_bytes);
        hash_int % &*BASE_FIELD_Q
    }

    fn point_add(p: &Point, q: &Point) -> Point {
        let field_p = &*BASE_FIELD_P;
        let d = Self::get_base_field_d();

        let p_x = &p.x;
        let p_y = &p.y;
        let p_z = &p.z;
        let p_t = &p.t;

        let q_x = &q.x;
        let q_y = &q.y;
        let q_z = &q.z;
        let q_t = &q.t;

        let a = Self::mul_mod(
            &Self::sub_mod(p_y, p_x, field_p),
            &Self::sub_mod(q_y, q_x, field_p),
            field_p,
        );
        let b = Self::mul_mod(
            &Self::add_mod(p_y, p_x, field_p),
            &Self::add_mod(q_y, q_x, field_p),
            field_p,
        );

        let two = BigUint::from(2u8);

        let c = Self::mul_mod(
            &Self::mul_mod(&two, p_t, field_p),
            &Self::mul_mod(q_t, &d, field_p),
            field_p,
        );

        let d_ = Self::mul_mod(&two, &Self::mul_mod(p_z, q_z, field_p), field_p);

        let e = Self::sub_mod(&b, &a, field_p);
        let f = Self::sub_mod(&d_, &c, field_p);
        let g = Self::add_mod(&d_, &c, field_p);
        let h = Self::add_mod(&b, &a, field_p);

        Point {
            x: Self::mul_mod(&e, &f, field_p),
            y: Self::mul_mod(&g, &h, field_p),
            z: Self::mul_mod(&f, &g, field_p),
            t: Self::mul_mod(&e, &h, field_p),
        }
    }

    fn point_multiply(scalar: &BigUint, point: Point) -> Point {
        let mut q = Self::identity();
        let mut addend = point;

        let mut k = scalar.clone();
        let one = BigUint::from(1u8);

        while k > BigUint::from(0u8) {
            if (&k & &one) == one {
                q = Self::point_add(&q, &addend);
            }
            addend = Self::point_add(&addend, &addend);
            k >>= 1;
        }

        q
    }

    fn point_equal(p: &Point, q: &Point) -> bool {
        let field_p = &*BASE_FIELD_P;

        let p_x = &p.x;
        let p_y = &p.y;
        let p_z = &p.z;

        let q_x = &q.x;
        let q_y = &q.y;
        let q_z = &q.z;

        // 射影座標の等価性:
        // P == Q <=> x1/z1 == x2/z2 && y1/z1 == y2/z1 (mod p)
        // <=> x1*z2 == x2*z1 && y1*z2 == y2*z1 (mod p)
        if Self::mul_mod(p_x, q_z, field_p) != Self::mul_mod(q_x, p_z, field_p) {
            return false;
        }
        if Self::mul_mod(p_y, q_z, field_p) != Self::mul_mod(q_y, p_z, field_p) {
            return false;
        }
        true
    }

    fn recover_x(y: &BigUint, sign: &BigUint) -> Option<BigUint> {
        let p = &*BASE_FIELD_P;
        let one = BigUint::from(1u8);

        // 0 <= y < p でなければダメ
        if y >= p {
            return None;
        }

        let y2 = Self::mul_mod(y, y, p);

        // x^2 = (y^2 - 1) / (1 + d y^2)
        let num = Self::sub_mod(&y2, &one, p); // y^2 - 1 (mod p)
        let den = Self::add_mod(&Self::mul_mod(&Self::get_base_field_d(), &y2, p), &one, p);
        let den_inv = Self::mod_p_inverse(&den);
        let x2 = Self::mul_mod(&num, &den_inv, p);

        if x2 == BigUint::from(0u8) {
            // x = 0 のときは sign が 0 なら OK, 1 なら reject
            return if *sign == BigUint::from(0u8) {
                Some(BigUint::from(0u8))
            } else {
                None
            };
        }

        // sqrt: x = x2^((p+3)/8)
        let exp = (&*BASE_FIELD_P + BigUint::from(3u8)) >> 3;
        let mut x = x2.modpow(&exp, p);

        // チェック (1回目)
        let mut check = Self::mul_mod(&x, &x, p);
        if check != x2 {
            // もう一回、sqrt(-1) を掛けてみる
            x = Self::mul_mod(&x, &*MOD_P_SQRT_M1, p);
            check = Self::mul_mod(&x, &x, p);
            if check != x2 {
                return None;
            }
        }

        // 符号ビットに合わせる
        let lsb_mask = BigUint::from(1u8);
        if (&x & &lsb_mask) != (sign & &lsb_mask) {
            x = p - &x;
        }

        Some(x)
    }

    fn point_compress(p: &Point) -> [u8; 32] {
        let field_p = &*BASE_FIELD_P;

        let z_inverse = Self::mod_p_inverse(&p.z);

        let x = Self::mul_mod(&p.x, &z_inverse, field_p);
        let mut y = Self::mul_mod(&p.y, &z_inverse, field_p);

        let x_sign = &x & BigUint::from(1u8);

        // y | (x_sign << 255)
        y |= &x_sign << 255;

        let y_bytes = y.to_bytes_le();
        let mut bytes = [0u8; 32];
        let len = y_bytes.len().min(32);
        bytes[..len].copy_from_slice(&y_bytes[..len]);
        bytes
    }

    fn point_decompress(bytes: [u8; 32]) -> Option<Point> {
        let field_p = &*BASE_FIELD_P;

        let mut y = BigUint::from_bytes_le(&bytes);

        // sign bit は bit 255 に入っている（LSB-firstで見たときの MSB）
        let sign = (&y >> 255) & BigUint::from(1u8);

        // y の 255 ビット目をクリアして、素の y 座標に戻す
        let mask = (BigUint::from(1u8) << 255) - BigUint::from(1u8);
        y &= mask;

        let x = Self::recover_x(&y, &sign)?;
        let z = BigUint::from(1u8);
        let t = Self::mul_mod(&x, &y, field_p);

        Some(Point { x, y, z, t })
    }

    fn secret_expand(secret: &[u8]) -> Option<(BigUint, [u8; 32])> {
        if secret.len() != 32 {
            return None;
        }

        let h = Self::sha512(secret);

        let mut a = BigUint::from_bytes_le(&h[0..32]);

        // clamp:
        // a &= (1 << 254) - 8;
        // a |= 1 << 254;
        let mask = (BigUint::from(1u8) << 254) - BigUint::from(8u8);
        a &= &mask;
        a |= BigUint::from(1u8) << 254;

        // 後ろ 32 バイトを prefix として返す
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);

        Some((a, prefix))
    }

    fn secret_to_public_key(secret: &[u8]) -> Option<[u8; 32]> {
        let (a, _prefix) = Self::secret_expand(secret)?;

        let base_point = Self::get_base_point();
        let a_b = Self::point_multiply(&a, base_point);
        let public_key_bytes = Self::point_compress(&a_b);

        Some(public_key_bytes)
    }

    pub(crate) fn sign(secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        let (a, prefix) = Self::secret_expand(secret)?;

        let base_point = Self::get_base_point();

        // A = a * B
        let public_key_bytes = Self::point_compress(&Self::point_multiply(&a, base_point.clone()));

        // r = SHA-512(prefix || message) mod q
        let mut r_input = Vec::with_capacity(32 + message.len());
        r_input.extend_from_slice(&prefix);
        r_input.extend_from_slice(message);
        let r = Self::sha512_mod_q(&r_input);

        // R = r * B
        let r_b = Self::point_multiply(&r, base_point.clone());
        let r_bytes = Self::point_compress(&r_b);

        // S = (r + SHA-512(R || A || M) * a) mod q
        let mut h_input = Vec::with_capacity(32 + 32 + message.len());
        h_input.extend_from_slice(&r_bytes);
        h_input.extend_from_slice(&public_key_bytes);
        h_input.extend_from_slice(message);
        let h = Self::sha512_mod_q(&h_input);
        let s = (r + h * a) % &*BASE_FIELD_Q;

        // シグネチャは R || S
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        let s_bytes = s.to_bytes_le();
        let len = s_bytes.len().min(32);
        signature[32..32 + len].copy_from_slice(&s_bytes[..len]);

        Some(signature)
    }

    pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != 32 || signature.len() != 64 {
            return false;
        }

        let a_point = match Self::point_decompress(public_key.try_into().unwrap()) {
            Some(p) => p,
            None => return false,
        };

        let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap();

        let r_point = match Self::point_decompress(r_bytes) {
            Some(p) => p,
            None => return false,
        };

        let s = BigUint::from_bytes_le(&s_bytes);
        if s >= *BASE_FIELD_Q {
            return false;
        }

        // h = SHA-512(R || A || M) mod q
        let mut h_input = Vec::with_capacity(32 + 32 + message.len());
        h_input.extend_from_slice(&r_bytes);
        h_input.extend_from_slice(public_key);
        h_input.extend_from_slice(message);
        let h = Self::sha512_mod_q(&h_input);

        let base_point = Self::get_base_point();

        // S * B == R + h * A
        let s_b = Self::point_multiply(&s, base_point);
        let h_a = Self::point_multiply(&h, a_point);
        let r_plus_h_a = Self::point_add(&r_point, &h_a);

        Self::point_equal(&s_b, &r_plus_h_a)
    }
}

mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut buf = String::new();
        for c in hex.chars() {
            if c.is_ascii_hexdigit() {
                buf.push(c);
                if buf.len() == 2 {
                    let byte = u8::from_str_radix(&buf, 16).expect("invalid hex");
                    bytes.push(byte);
                    buf.clear();
                }
            }
        }
        bytes
    }

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
            let x = BigUint::from(i);
            let inv_x = Ed25519::mod_p_inverse(&x);
            let product = (&x * &inv_x) % &*BASE_FIELD_P;
            assert_eq!(product, BigUint::from(1u8));
        }
    }

    #[test]
    fn test_get_base_field_d() {
        let d = Ed25519::get_base_field_d();

        // 仕様で決まっている Ed25519 の d
        let expected = BigUint::parse_bytes(
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
        let sign = BigUint::from(0u8);
        let x = Ed25519::recover_x(&y, &sign);
        assert!(x.is_none());
    }

    #[test]
    fn test_recover_x_identity_point_x_0_y_1() {
        // 単位元 (x, y) = (0, 1) のテスト
        // 符号ビット 0 -> x = 0 が返ってくる
        // 符号ビット 1 -> 非正規形として None
        let y = BigUint::from(1u8);
        let sign0 = BigUint::from(0u8);
        let x0 = Ed25519::recover_x(&y, &sign0);
        assert_eq!(x0, Some(BigUint::from(0u8)));
        let sign1 = BigUint::from(1u8);
        let x1 = Ed25519::recover_x(&y, &sign1);
        assert!(x1.is_none());
    }

    #[test]
    fn test_recover_x_basepoint() {
        // Ed25519 のベースポイント B の座標
        // Bx, By は仕様で決まっている定数
        // B = (1511222..., 4631683... )
        let y = BigUint::parse_bytes(
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960",
            10,
        )
        .unwrap();
        let x_expected = BigUint::parse_bytes(
            b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
            10,
        )
        .unwrap();

        // 公開鍵エンコード時と同じく、sign は x の LSB（最下位ビット）
        let sign = &x_expected & BigUint::from(1u8);
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
        let expected_a = BigUint::parse_bytes(
            b"39325648866980652792715009169219496062012184734522019333892538943312776480336",
            10,
        )
        .expect("failed to parse expected a for zero seed");

        assert_eq!(a, expected_a);

        let expected_prefix: [u8; 32] = [
            0x0a, 0x6a, 0x85, 0xea, 0xa6, 0x42, 0xda, 0xc8, 0x35, 0x42, 0x4b, 0x5d, 0x7c, 0x8d,
            0x63, 0x7c, 0x00, 0x40, 0x8c, 0x7a, 0x73, 0xda, 0x67, 0x2b, 0x7f, 0x49, 0x85, 0x21,
            0x42, 0x0b, 0x6d, 0xd3,
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

        let expected_a = BigUint::parse_bytes(
            b"50459379271018302582465998844449622265826330103819895252966304478993432089656",
            10,
        )
        .expect("failed to parse expected a for incrementing seed");

        assert_eq!(a, expected_a);

        let expected_prefix: [u8; 32] = [
            0xa9, 0xd7, 0x18, 0x62, 0xa3, 0xe5, 0x74, 0x6b, 0x57, 0x1b, 0xe3, 0xd1, 0x87, 0xb0,
            0x04, 0x10, 0x46, 0xf5, 0x2e, 0xbd, 0x85, 0x0c, 0x7c, 0xbd, 0x5f, 0xde, 0x8e, 0xe3,
            0x84, 0x73, 0xb6, 0x49,
        ];

        assert_eq!(prefix, expected_prefix);
    }

    #[test]
    fn test_sha512_mod_q_range_and_determinism() {
        let input = b"hello ed25519";
        let r1 = Ed25519::sha512_mod_q(input);
        let r2 = Ed25519::sha512_mod_q(input);

        // 同じ入力なら同じ値
        assert_eq!(r1, r2);

        // 0 <= r < q になっていること
        assert!(r1 < *BASE_FIELD_Q);
    }

    #[test]
    fn test_identity_compress_round_trip() {
        // 単位元は (0,1,1,0) のはずで、compress → decompress で不変であること
        let id = Ed25519::identity();
        let enc = Ed25519::point_compress(&id);
        let dec = Ed25519::point_decompress(enc).expect("identity should decompress");

        assert!(Ed25519::point_equal(&id, &dec));
    }

    #[test]
    fn test_point_decompress_basepoint_and_compress_roundtrip() {
        // Ed25519 のベースポイントの圧縮表現（RFC 実装でおなじみの 0x58 0x66...）
        let mut base_bytes = [0x66u8; 32];
        base_bytes[0] = 0x58;

        let p = Ed25519::point_decompress(base_bytes.clone()).expect("basepoint should decompress");

        // compress して元に戻ること
        let enc = Ed25519::point_compress(&p);
        assert_eq!(enc, base_bytes);
    }

    #[test]
    fn test_point_add_identity_is_neutral_element() {
        // ベースポイントを使って「単位元が中立元」になっているかを確認
        let mut base_bytes = [0x66u8; 32];
        base_bytes[0] = 0x58;
        let p = Ed25519::point_decompress(base_bytes).expect("basepoint should decompress");

        let id = Ed25519::identity();

        let left = Ed25519::point_add(&id, &p);
        let right = Ed25519::point_add(&p, &id);

        assert!(Ed25519::point_equal(&left, &p));
        assert!(Ed25519::point_equal(&right, &p));
    }

    #[test]
    fn test_point_equal_true_and_false() {
        let mut base_bytes = [0x66u8; 32];
        base_bytes[0] = 0x58;

        let p1 = Ed25519::point_decompress(base_bytes.clone()).expect("basepoint");
        let p2 = Ed25519::point_decompress(base_bytes).expect("basepoint again");
        let id = Ed25519::identity();

        assert!(Ed25519::point_equal(&p1, &p2));
        assert!(!Ed25519::point_equal(&p1, &id));
    }

    #[test]
    fn test_point_multiply_consistent_with_repeated_addition() {
        // 2B = B + B になることを確認して、point_multiply と point_add の整合性をチェック
        let mut base_bytes = [0x66u8; 32];
        base_bytes[0] = 0x58;

        let b_for_mul = Ed25519::point_decompress(base_bytes.clone()).expect("basepoint for mul");
        let b1 = Ed25519::point_decompress(base_bytes.clone()).expect("basepoint for add 1");
        let b2 = Ed25519::point_decompress(base_bytes).expect("basepoint for add 2");

        let two_b_mul = Ed25519::point_multiply(&BigUint::from(2u8), b_for_mul);
        let two_b_add = Ed25519::point_add(&b1, &b2);
        assert!(Ed25519::point_equal(&two_b_mul, &two_b_add));
    }

    #[test]
    fn test_point_compress_decompress_round_trip_random_like_scalar() {
        // 適当なスカラー倍された点でも compress → decompress が保たれることを確認
        let b = Ed25519::get_base_point();
        let scalar = BigUint::from(123u32);
        let p = Ed25519::point_multiply(&scalar, b);
        let enc = Ed25519::point_compress(&p);
        let dec = Ed25519::point_decompress(enc).expect("decompress after scalar multiply");
        assert!(Ed25519::point_equal(&p, &dec));
    }

    #[test]
    fn test_secret_to_public_key_rfc8032_test1() {
        // RFC 8032, Section 7.1, Test 1
        // SECRET KEY:
        // 9d61b19deffd5a60ba844af492ec2cc4
        // 4449c5697b326919703bac031cae7f60
        // PUBLIC KEY:
        // d75a980182b10ab7d54bfed3c964073a
        // 0ee172f3daa62325af021a68f707511a

        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        let expected_public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];

        let public_key = Ed25519::secret_to_public_key(&secret)
            .expect("secret_to_public_key should return Some for a valid 32-byte secret");

        assert_eq!(public_key, expected_public_key);
    }

    #[test]
    fn test_sign_and_verify_rfc8032_test1() {
        // RFC 8032, Section 7.1, Test 1
        //    ALGORITHM:
        //    Ed25519
        //
        //    SECRET KEY:
        //    9d61b19deffd5a60ba844af492ec2cc4
        //    4449c5697b326919703bac031cae7f60
        //
        //    PUBLIC KEY:
        //    d75a980182b10ab7d54bfed3c964073a
        //    0ee172f3daa62325af021a68f707511a
        //
        //    MESSAGE (length 0 bytes):
        //
        //    SIGNATURE:
        //    e5564300c360ac729086e2cc806e828a
        //    84877f1eb8e5d974d873e06522490155
        //    5fb8821590a33bacc61e39701cf9b46b
        //    d25bf5f0595bbe24655141438e7a100b

        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];

        let expected_signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let message: [u8; 0] = [];

        // 公開鍵の導出が RFC の値と一致すること
        let derived_public_key = Ed25519::secret_to_public_key(&secret)
            .expect("secret_to_public_key should succeed for valid seed");
        assert_eq!(derived_public_key, public_key);

        // 署名が RFC のテストベクタと一致すること
        let signature = Ed25519::sign(&secret, &message).expect("sign should succeed");
        assert_eq!(signature, expected_signature);

        // verify が true を返すこと
        assert!(Ed25519::verify(&public_key, &message, &signature));

        // 署名を 1 ビット壊すと verify が false になること
        let mut bad_signature = signature;
        bad_signature[0] ^= 0x01;
        assert!(!Ed25519::verify(&public_key, &message, &bad_signature));
    }

    #[test]
    fn test_sign_and_verify_rfc8032_test2() {
        // RFC 8032 / Ed25519 TEST 2
        // SECRET KEY:
        // 4ccd089b28ff96da9db6c346ec114e0f
        // 5b8a319f35aba624da8cf6ed4fb8a6fb
        // PUBLIC KEY:
        // 3d4017c3e843895a92b70aa74d1b7ebc
        // 9c982ccf2ec4968cc0cd55f12af4660c
        // MESSAGE (length 1 byte):
        // 72
        // SIGNATURE:
        // 92a009a9f0d4cab8720e820b5f642540
        // a2b27b5416503f8fb3762223ebdb69da
        // 085ac1e43e15996e458f3613d0f11d8c
        // 387b2eaeb4302aeeb00d291612bb0c00

        let secret_vec = hex_to_bytes(
            "4ccd089b28ff96da9db6c346ec114e0f\
             5b8a319f35aba624da8cf6ed4fb8a6fb",
        );
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_vec);

        let public_key_vec = hex_to_bytes(
            "3d4017c3e843895a92b70aa74d1b7ebc\
             9c982ccf2ec4968cc0cd55f12af4660c",
        );
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_vec);

        let message: [u8; 1] = [0x72];

        let expected_signature = hex_to_bytes(
            "92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00",
        );

        // 公開鍵の導出がテストベクタと一致すること
        let derived_public_key = Ed25519::secret_to_public_key(&secret)
            .expect("secret_to_public_key should succeed for valid seed");
        assert_eq!(derived_public_key, public_key);

        // 署名がテストベクタと一致すること
        let signature = Ed25519::sign(&secret, &message).expect("sign should succeed");
        assert_eq!(signature.to_vec(), expected_signature);

        // verify が true を返すこと
        assert!(Ed25519::verify(&public_key, &message, &signature));

        // 署名を 1 ビット壊すと verify が false になること
        let mut bad_signature = signature;
        bad_signature[0] ^= 0x01;
        assert!(!Ed25519::verify(&public_key, &message, &bad_signature));
    }

    #[test]
    fn test_sign_and_verify_rfc8032_test3() {
        // RFC 8032 / Ed25519 TEST 3
        // SECRET KEY:
        // c5aa8df43f9f837bedb7442f31dcb7b1
        // 66d38535076f094b85ce3a2e0b4458f7
        // PUBLIC KEY:
        // fc51cd8e6218a1a38da47ed00230f058
        // 0816ed13ba3303ac5deb911548908025
        // MESSAGE (length 2 bytes):
        // af82
        // SIGNATURE:
        // 6291d657deec24024827e69c3abe01a3
        // 0ce548a284743a445e3680d7db5ac3ac
        // 18ff9b538d16f290ae67f760984dc659
        // 4a7c15e9716ed28dc027beceea1ec40a

        let secret_vec = hex_to_bytes(
            "c5aa8df43f9f837bedb7442f31dcb7b1\
             66d38535076f094b85ce3a2e0b4458f7",
        );
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_vec);

        let public_key_vec = hex_to_bytes(
            "fc51cd8e6218a1a38da47ed00230f058\
             0816ed13ba3303ac5deb911548908025",
        );
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_vec);

        let message: [u8; 2] = [0xaf, 0x82];

        let expected_signature = hex_to_bytes(
            "6291d657deec24024827e69c3abe01a3\
             0ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc659\
             4a7c15e9716ed28dc027beceea1ec40a",
        );

        let derived_public_key = Ed25519::secret_to_public_key(&secret)
            .expect("secret_to_public_key should succeed for valid seed");
        assert_eq!(derived_public_key, public_key);

        let signature = Ed25519::sign(&secret, &message).expect("sign should succeed");
        assert_eq!(signature.to_vec(), expected_signature);

        assert!(Ed25519::verify(&public_key, &message, &signature));

        let mut bad_signature = signature;
        bad_signature[0] ^= 0x01;
        assert!(!Ed25519::verify(&public_key, &message, &bad_signature));
    }

    #[test]
    fn test_sign_and_verify_rfc8032_test1024() {
        // RFC 8032 / Ed25519 TEST 1024 (message length 1023 bytes)

        let secret_vec = hex_to_bytes(
            "f5e5767cf153319517630f226876b86c\
             8160cc583bc013744c6bf255f5cc0ee5",
        );
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_vec);

        let public_key_vec = hex_to_bytes(
            "278117fc144c72340f67d0f2316e8386\
             ceffbf2b2428c9c51fef7c597f1d426e",
        );
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_vec);

        let message_hex = "
            08b8b2b733424243760fe426a4b54908
            632110a66c2f6591eabd3345e3e4eb98
            fa6e264bf09efe12ee50f8f54e9f77b1
            e355f6c50544e23fb1433ddf73be84d8
            79de7c0046dc4996d9e773f4bc9efe57
            38829adb26c81b37c93a1b270b20329d
            658675fc6ea534e0810a4432826bf58c
            941efb65d57a338bbd2e26640f89ffbc
            1a858efcb8550ee3a5e1998bd177e93a
            7363c344fe6b199ee5d02e82d522c4fe
            ba15452f80288a821a579116ec6dad2b
            3b310da903401aa62100ab5d1a36553e
            06203b33890cc9b832f79ef80560ccb9
            a39ce767967ed628c6ad573cb116dbef
            efd75499da96bd68a8a97b928a8bbc10
            3b6621fcde2beca1231d206be6cd9ec7
            aff6f6c94fcd7204ed3455c68c83f4a4
            1da4af2b74ef5c53f1d8ac70bdcb7ed1
            85ce81bd84359d44254d95629e9855a9
            4a7c1958d1f8ada5d0532ed8a5aa3fb2
            d17ba70eb6248e594e1a2297acbbb39d
            502f1a8c6eb6f1ce22b3de1a1f40cc24
            554119a831a9aad6079cad88425de6bd
            e1a9187ebb6092cf67bf2b13fd65f270
            88d78b7e883c8759d2c4f5c65adb7553
            878ad575f9fad878e80a0c9ba63bcbcc
            2732e69485bbc9c90bfbd62481d9089b
            eccf80cfe2df16a2cf65bd92dd597b07
            07e0917af48bbb75fed413d238f5555a
            7a569d80c3414a8d0859dc65a46128ba
            b27af87a71314f318c782b23ebfe808b
            82b0ce26401d2e22f04d83d1255dc51a
            ddd3b75a2b1ae0784504df543af8969b
            e3ea7082ff7fc9888c144da2af58429e
            c96031dbcad3dad9af0dcbaaaf268cb8
            fcffead94f3c7ca495e056a9b47acdb7
            51fb73e666c6c655ade8297297d07ad1
            ba5e43f1bca32301651339e22904cc8c
            42f58c30c04aafdb038dda0847dd988d
            cda6f3bfd15c4b4c4525004aa06eeff8
            ca61783aacec57fb3d1f92b0fe2fd1a8
            5f6724517b65e614ad6808d6f6ee34df
            f7310fdc82aebfd904b01e1dc54b2927
            094b2db68d6f903b68401adebf5a7e08
            d78ff4ef5d63653a65040cf9bfd4aca7
            984a74d37145986780fc0b16ac451649
            de6188a7dbdf191f64b5fc5e2ab47b57
            f7f7276cd419c17a3ca8e1b939ae49e4
            88acba6b965610b5480109c8b17b80e1
            b7b750dfc7598d5d5011fd2dcc5600a3
            2ef5b52a1ecc820e308aa342721aac09
            43bf6686b64b2579376504ccc493d97e
            6aed3fb0f9cd71a43dd497f01f17c0e2
            cb3797aa2a2f256656168e6c496afc5f
            b93246f6b1116398a346f1a641f3b041
            e989f7914f90cc2c7fff357876e506b5
            0d334ba77c225bc307ba537152f3f161
            0e4eafe595f6d9d90d11faa933a15ef1
            369546868a7f3a45a96768d40fd9d034
            12c091c6315cf4fde7cb68606937380d
            b2eaaa707b4c4185c32eddcdd306705e
            4dc1ffc872eeee475a64dfac86aba41c
            0618983f8741c5ef68d3a101e8a3b8ca
            c60c905c15fc910840b94c00a0b9d0
        ";

        let message = hex_to_bytes(message_hex);
        assert_eq!(message.len(), 1023);

        let expected_signature = hex_to_bytes(
            "0aab4c900501b3e24d7cdf4663326a3a\
             87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b\
             5e8fcd4f681e30a6ac00a9704a188a03",
        );

        let derived_public_key = Ed25519::secret_to_public_key(&secret)
            .expect("secret_to_public_key should succeed for valid seed");
        assert_eq!(derived_public_key, public_key);

        let signature = Ed25519::sign(&secret, &message).expect("sign should succeed");
        assert_eq!(signature.to_vec(), expected_signature);

        assert!(Ed25519::verify(&public_key, &message, &signature));

        let mut bad_signature = signature;
        bad_signature[0] ^= 0x01;
        assert!(!Ed25519::verify(&public_key, &message, &bad_signature));
    }
}
