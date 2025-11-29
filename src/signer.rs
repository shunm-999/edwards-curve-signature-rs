use crate::algorithm::Ed25519;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SignatureAlgorithm {
    Ed448,
    Ed25519,
}

pub(crate) trait Signer {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]>;
}

pub(crate) trait Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub(crate) struct EdDsaSignature {
    algorithm: SignatureAlgorithm,
}

impl EdDsaSignature {
    pub(crate) fn new(algorithm: SignatureAlgorithm) -> Self {
        EdDsaSignature { algorithm }
    }
}

impl Signer for EdDsaSignature {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                todo!()
            }
            SignatureAlgorithm::Ed25519 => Ed25519::sign(secret, message),
        }
    }
}

impl Verifier for EdDsaSignature {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                todo!()
            }
            SignatureAlgorithm::Ed25519 => Ed25519::verify(public_key, message, signature),
        }
    }
}
