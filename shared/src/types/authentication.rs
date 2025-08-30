// SHARED TYPES IMPLEMENTATIONS - shared/src/types/authentication.rs
pub mod authentication {
    //! Authentication system types and definitions
    
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    use zeroize::{Zeroize, ZeroizeOnDrop};
    
    /// Authentication method configuration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum AuthenticationMethod {
        USBKey {
            device_id: String,
            key_slot: u8,
        },
        Password {
            hash: String,
            salt: Vec<u8>,
        },
    }
    
    /// User credentials for authentication
    #[derive(Debug, Clone, ZeroizeOnDrop, Serialize, Deserialize)]
    pub struct UserCredentials {
        pub credential_id: Uuid,
        pub credential_data: Vec<u8>,
        pub credential_type: CredentialType,
        pub expiration: Option<DateTime<Utc>>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum CredentialType {
        USBKeyData,
        PasswordHash,
        CertificateData,
    }
    
    /// Authentication result information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticationResult {
        pub success: bool,
        pub profile_id: Uuid,
        pub session_token: Option<String>,
        pub permissions: Vec<Permission>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Permission {
        SystemConfiguration,
        ApplicationInstallation,
        HardwareAccess,
        NetworkAccess,
        StorageAccess,
    }
    
    /// USB key device information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct USBKeyDevice {
        pub device_id: String,
        pub vendor_id: u16,
        pub product_id: u16,
        pub serial_number: String,
        pub key_capacity: u64,
    }
}
