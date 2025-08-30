// SHARED CRYPTO MODULE ORGANIZATION - shared/src/crypto/mod.rs
pub mod shared_crypto {
    //! Cryptographic utilities for the complete isolation system
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256, Sha512};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
    use ring::{digest, hmac, rand};
    use std::sync::Arc;
    
    // Crypto component exports
    pub use self::verification::{SignatureVerification, IntegrityVerification, ComponentVerification};
    pub use self::encryption::{DataEncryption, StorageEncryption, CommunicationEncryption};
    pub use self::key_derivation::{KeyDerivationFunction, DerivedKey, KeyDerivationContext};
    pub use self::random::{SecureRandom, RandomGenerator, EntropySource};
    
    // Crypto module declarations
    pub mod verification;
    pub mod encryption;
    pub mod key_derivation;
    pub mod random;
    
    /// Signature algorithm enumeration
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SignatureAlgorithm {
        Ed25519,
        RSA2048,
        RSA4096,
    }
    
    /// Hash algorithm enumeration  
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum HashAlgorithm {
        SHA256,
        SHA512,
        Blake3,
    }
    
    /// Verification context for cryptographic operations
    #[derive(Debug, Clone)]
    pub struct VerificationContext {
        pub signature_algorithm: SignatureAlgorithm,
        pub hash_algorithm: HashAlgorithm,
        pub verification_key: Arc<PublicKey>,
    }
}
