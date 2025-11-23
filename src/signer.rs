use crate::algorithm::Ed25519;

#[derive(Debug, Clone, Copy)]
enum SignatureAlgorithm {
    Ed448,
    Ed25519,
}

pub(crate) trait Signer {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]>;
}

pub(crate) trait Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub(crate) struct EdDsaSigner {
    algorithm: SignatureAlgorithm,
    ed25519: Ed25519,
}

pub(crate) struct EdDsaVerifier {
    algorithm: SignatureAlgorithm,
    ed25519: Ed25519,
}

impl EdDsaSigner {
    fn new(algorithm: SignatureAlgorithm) -> Self {
        EdDsaSigner {
            algorithm,
            ed25519: Ed25519 {},
        }
    }
}

impl Signer for EdDsaSigner {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                let signer = Ed448Signer {};
                signer.sign(secret, message)
            }
            SignatureAlgorithm::Ed25519 => {
                let signer = Ed25519Signer {
                    ed25519: &self.ed25519,
                };
                signer.sign(secret, message)
            }
        }
    }
}

impl Verifier for EdDsaVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self.algorithm {
            SignatureAlgorithm::Ed448 => {
                let verifier = Ed448Verifier {};
                verifier.verify(public_key, message, signature)
            }
            SignatureAlgorithm::Ed25519 => {
                let verifier = Ed25519Verifier {
                    ed25519: &self.ed25519,
                };
                verifier.verify(public_key, message, signature)
            }
        }
    }
}

struct Ed448Signer {}
struct Ed448Verifier {}

struct Ed25519Signer<'a> {
    ed25519: &'a Ed25519,
}

struct Ed25519Verifier<'a> {
    ed25519: &'a Ed25519,
}

impl Signer for Ed448Signer {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        // Implement Ed448 signing logic here
        todo!()
    }
}

impl Verifier for Ed448Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Implement Ed448 verification logic here
        true
    }
}

impl Signer for Ed25519Signer<'_> {
    fn sign(&self, secret: &[u8], message: &[u8]) -> Option<[u8; 64]> {
        // Implement Ed25519 signing logic here
        Ed25519Signer::sign(self, secret, message)
    }
}

impl Verifier for Ed25519Verifier<'_> {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Implement Ed25519 verification logic here
        Ed25519Verifier::verify(self, public_key, message, signature)
    }
}
