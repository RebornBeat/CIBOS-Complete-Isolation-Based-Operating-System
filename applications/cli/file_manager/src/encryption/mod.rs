// cibos/applications/cli/file_manager/src/encryption/mod.rs
pub mod encryption {
    //! File encryption and decryption with automatic key management
    //!
    //! This module provides transparent file encryption capabilities
    //! that integrate with the isolation boundaries to ensure
    //! encrypted files remain secure across application boundaries.

    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}};
    use uuid::Uuid;
    use std::sync::Arc;
    use std::path::PathBuf;
    use std::collections::HashMap;

    // Cryptographic dependencies
    use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore, AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305};
    use ring::{digest, rand};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    // Component exports for encryption management
    pub use self::manager::{FileEncryptionManager, EncryptionConfiguration, KeyProvider};
    pub use self::operations::{EncryptedFileOperations, EncryptionOperation, DecryptionOperation};
    pub use self::keys::{KeyManager, EncryptionKey, KeyDerivation, KeyStorage};
    pub use self::algorithms::{EncryptionAlgorithm, CipherEngine, EncryptionParameters};

    // Internal encryption modules
    pub mod manager;
    pub mod operations;  
    pub mod keys;
    pub mod algorithms;

    /// File encryption manager with automatic key handling
    #[derive(Debug)]
    pub struct FileEncryptionManager {
        pub key_manager: Arc<KeyManager>,
        pub cipher_engine: Arc<CipherEngine>,
        pub encryption_configuration: EncryptionConfiguration,
    }

    /// Encryption status for files and operations
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum EncryptionStatus {
        Unencrypted,
        Encrypted { algorithm: super::EncryptionAlgorithm, key_id: Uuid },
        EncryptionInProgress { progress_percentage: u8 },
        DecryptionInProgress { progress_percentage: u8 },
        EncryptionFailed { error_message: String },
    }

    /// CLI encryption interface for user-facing encryption operations
    #[derive(Debug)]
    pub struct CLIEncryptionInterface {
        pub supported_algorithms: Vec<super::EncryptionAlgorithm>,
        pub default_algorithm: super::EncryptionAlgorithm,
        pub key_derivation_iterations: u32,
    }
}

