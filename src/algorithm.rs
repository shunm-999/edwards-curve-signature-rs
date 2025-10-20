use sha2::{Digest, Sha512};

pub(crate) struct Ed25519 {}

impl Ed25519 {
    fn sha512(s: &[u8]) -> [u8; 64] {
        let mut sha512 = Sha512::default();

        sha512.update(s);
        sha512.finalize_reset().into()
    }
}
