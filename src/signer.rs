use crate::algorithm::Ed25519;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SignatureAlgorithm {
    Ed448,
    Ed25519,
}

pub(crate) trait Sign {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]>;
}

pub(crate) trait Verify {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub(crate) trait GeneratePublicKey {
    fn generate_public_key(&self, secret: &[u8]) -> Option<[u8; 32]>;
}

pub(crate) struct EdDsaSignature {
    algorithm: SignatureAlgorithm,
}

impl EdDsaSignature {
    pub(crate) fn new(algorithm: SignatureAlgorithm) -> Self {
        EdDsaSignature { algorithm }
    }
}

impl Sign for EdDsaSignature {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                todo!()
            }
            SignatureAlgorithm::Ed25519 => Ed25519::sign(secret, message),
        }
    }
}

impl Verify for EdDsaSignature {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                todo!()
            }
            SignatureAlgorithm::Ed25519 => Ed25519::verify(public_key, message, signature),
        }
    }
}

impl GeneratePublicKey for EdDsaSignature {
    fn generate_public_key(&self, secret: &[u8]) -> Option<[u8; 32]> {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                todo!()
            }
            SignatureAlgorithm::Ed25519 => Ed25519::generate_public_key(secret),
        }
    }
}
