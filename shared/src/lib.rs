// =============================================================================
// SHARED FOUNDATION - shared/src/lib.rs
// Complete isolation system shared utilities and type definitions
// =============================================================================

// External dependencies for shared utilities
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;

// Cryptographic dependencies
use sha2::{Digest, Sha256, Sha512};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore, AeadInPlace};
use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use ring::{digest, hmac, rand as ring_rand};

// Module declarations
pub mod types;
pub mod crypto;
pub mod protocols;
pub mod utils;

// =============================================================================
// SHARED TYPE DEFINITIONS
// =============================================================================

/// Hardware platform identification for cross-platform compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwarePlatform {
    Desktop,
    Laptop,
    Server,
    Mobile,
    Tablet,
    Embedded,
    SingleBoard,
}

/// Processor architecture for compilation targeting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorArchitecture {
    X86_64,
    AArch64,
    X86,
    RiscV64,
}

/// Security capabilities available on hardware platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCapabilities {
    pub hardware_virtualization: bool,
    pub hardware_encryption: bool,
    pub trusted_platform_module: bool,
    pub secure_boot_support: bool,
    pub memory_encryption: bool,
}

/// Isolation level enforcement (always maximum - no compromise modes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    Complete, // Only level supported - mathematical isolation guarantees
}

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

/// User profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub profile_id: Uuid,
    pub profile_name: String,
    pub authentication: AuthenticationMethod,
    pub isolation_config: IsolationConfiguration,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}

/// Isolation boundary configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfiguration {
    pub memory_boundary: MemoryBoundary,
    pub storage_boundary: StorageBoundary,
    pub network_boundary: NetworkBoundary,
    pub process_boundary: ProcessBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBoundary {
    pub base_address: u64,
    pub size: u64,
    pub protection_flags: MemoryProtectionFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBoundary {
    pub allowed_paths: Vec<String>,
    pub encryption_required: bool,
    pub read_only_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBoundary {
    pub allowed_destinations: Vec<String>,
    pub proxy_required: bool,
    pub traffic_isolation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBoundary {
    pub cpu_allocation: CpuAllocation,
    pub priority_level: ProcessPriority,
    pub isolation_level: IsolationLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAllocation {
    pub percentage: u8,
    pub dedicated_cores: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessPriority {
    System,
    User,
    Background,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtectionFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

// =============================================================================
// ERROR DEFINITIONS
// =============================================================================

/// Comprehensive error types for the entire isolation system
#[derive(Error, Debug)]
pub enum SystemError {
    #[error("CIBIOS firmware error: {message}")]
    CIBIOSError { message: String },
    
    #[error("CIBOS kernel error: {message}")]
    CIBOSError { message: String },
    
    #[error("Hardware initialization error: {message}")]
    HardwareError { message: String },
    
    #[error("Isolation boundary violation: {message}")]
    IsolationError { message: String },
    
    #[error("Authentication failure: {message}")]
    AuthenticationError { message: String },
    
    #[error("Cryptographic operation failed: {message}")]
    CryptographicError { message: String },
    
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },
}

// =============================================================================
// CRYPTOGRAPHIC UTILITIES
// =============================================================================

/// Cryptographic verification context for system components
#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub signature_algorithm: SignatureAlgorithm,
    pub hash_algorithm: HashAlgorithm,
    pub verification_key: Arc<PublicKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
    RSA2048,
    RSA4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    SHA256,
    SHA512,
    Blake3,
}

/// Secure data encryption for storage and communication
#[derive(Debug, Clone)]
pub struct EncryptionContext {
    pub algorithm: EncryptionAlgorithm,
    pub key: Arc<EncryptionKey>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct EncryptionKey {
    key_material: Vec<u8>,
    key_id: Uuid,
}

// =============================================================================
// COMMUNICATION PROTOCOLS
// =============================================================================

/// Handoff protocol for CIBIOS to CIBOS transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffProtocol {
    pub handoff_id: Uuid,
    pub cibios_version: String,
    pub hardware_config: HardwareConfiguration,
    pub isolation_boundaries: IsolationConfiguration,
    pub verification_chain: Vec<VerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareConfiguration {
    pub platform: HardwarePlatform,
    pub architecture: ProcessorArchitecture,
    pub capabilities: SecurityCapabilities,
    pub memory_layout: MemoryLayout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLayout {
    pub total_memory: u64,
    pub available_memory: u64,
    pub reserved_regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start_address: u64,
    pub size: u64,
    pub region_type: MemoryRegionType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryRegionType {
    Firmware,
    Kernel,
    Application,
    Hardware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub component_name: String,
    pub verification_passed: bool,
    pub signature_valid: bool,
    pub integrity_hash: String,
}

/// Secure IPC channel for isolated component communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureChannel {
    pub channel_id: Uuid,
    pub source_component: ComponentId,
    pub destination_component: ComponentId,
    pub encryption_context: ChannelEncryption,
    pub message_protocol: MessageProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentId {
    pub component_name: String,
    pub isolation_boundary: Uuid,
    pub process_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEncryption {
    pub encryption_enabled: bool,
    pub key_exchange_method: KeyExchangeMethod,
    pub cipher: EncryptionAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchangeMethod {
    ECDH,
    RSA,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageProtocol {
    Request { message_id: Uuid, data: Vec<u8> },
    Response { request_id: Uuid, data: Vec<u8> },
    Notification { event_type: String, data: Vec<u8> },
}

// =============================================================================
// CONFIGURATION MANAGEMENT
// =============================================================================

/// System-wide configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfiguration {
    pub platform: HardwarePlatform,
    pub architecture: ProcessorArchitecture,
    pub isolation_config: IsolationConfiguration,
    pub security_config: SecurityConfiguration,
    pub authentication_config: AuthenticationConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfiguration {
    pub hardware_acceleration: bool,
    pub cryptographic_verification: bool,
    pub tamper_detection: bool,
    pub secure_storage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfiguration {
    pub usb_key_required: bool,
    pub password_fallback: bool,
    pub key_device_timeout: Duration,
}

use std::time::Duration;

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

impl SystemConfiguration {
    /// Create default configuration for specified platform
    pub fn default_for_platform(platform: HardwarePlatform) -> Self {
        Self {
            platform,
            architecture: ProcessorArchitecture::X86_64, // Default, will be detected at runtime
            isolation_config: IsolationConfiguration::maximum_security(),
            security_config: SecurityConfiguration::maximum_security(),
            authentication_config: AuthenticationConfiguration::secure_default(),
        }
    }

    /// Validate configuration against hardware capabilities
    pub fn validate_against_hardware(&self, capabilities: &SecurityCapabilities) -> Result<(), SystemError> {
        if self.security_config.hardware_acceleration && !capabilities.hardware_virtualization {
            return Err(SystemError::ConfigurationError {
                message: "Hardware acceleration requested but not available".to_string(),
            });
        }
        Ok(())
    }
}

impl IsolationConfiguration {
    /// Create maximum security isolation configuration
    pub fn maximum_security() -> Self {
        Self {
            memory_boundary: MemoryBoundary {
                base_address: 0,
                size: 0, // Will be set during initialization
                protection_flags: MemoryProtectionFlags {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            },
            storage_boundary: StorageBoundary {
                allowed_paths: Vec::new(), // Restrictive by default
                encryption_required: true,
                read_only_paths: Vec::new(),
            },
            network_boundary: NetworkBoundary {
                allowed_destinations: Vec::new(), // Restrictive by default
                proxy_required: true,
                traffic_isolation: true,
            },
            process_boundary: ProcessBoundary {
                cpu_allocation: CpuAllocation {
                    percentage: 100, // Fair sharing by default
                    dedicated_cores: Vec::new(),
                },
                priority_level: ProcessPriority::User,
                isolation_level: IsolationLevel::Complete,
            },
        }
    }
}

impl SecurityConfiguration {
    /// Create maximum security configuration
    pub fn maximum_security() -> Self {
        Self {
            hardware_acceleration: false, // Conservative default - user can enable
            cryptographic_verification: true,
            tamper_detection: true,
            secure_storage: true,
        }
    }
}

impl AuthenticationConfiguration {
    /// Create secure default authentication configuration
    pub fn secure_default() -> Self {
        Self {
            usb_key_required: true,
            password_fallback: false, // USB key is primary method
            key_device_timeout: Duration::from_secs(30),
        }
    }
}

// =============================================================================
// PUBLIC RE-EXPORTS
// =============================================================================

// Hardware abstraction exports
pub use types::hardware::{
    HardwarePlatform, ProcessorArchitecture, SecurityCapabilities,
    DisplayCapabilities, InputCapabilities, AudioCapabilities,
    NetworkCapabilities, StorageCapabilities
};

// Isolation system exports
pub use types::isolation::{
    IsolationLevel, ProcessIsolationLevel, ApplicationBoundary,
    BoundaryConfiguration, IsolationResult, ResourceIsolation,
    IsolationConfiguration, MemoryBoundary, StorageBoundary,
    NetworkBoundary, ProcessBoundary
};

// Authentication system exports
pub use types::authentication::{
    AuthenticationMethod, UserCredentials, AuthenticationResult,
    USBKeyDevice, AuthenticationConfiguration
};

// User profile exports
pub use types::profiles::{
    UserProfile, ProfileConfiguration, ProfileCapabilities,
    DesktopProfile, MobileProfile, CLIProfile
};

// Error handling exports
pub use types::error::{
    SystemError, CIBIOSError, CIBOSError, KernelError,
    ApplicationError, HardwareError, AuthenticationError,
    IsolationError, ConfigurationError
};

// Cryptographic exports
pub use crypto::verification::{
    SignatureAlgorithm, HashAlgorithm, VerificationContext,
    SignatureVerification, IntegrityVerification, ComponentVerification
};

pub use crypto::encryption::{
    EncryptionAlgorithm, EncryptionContext, EncryptionKey,
    DataEncryption, StorageEncryption, CommunicationEncryption
};

// Communication protocol exports
pub use protocols::handoff::{
    HandoffProtocol, HandoffData, CIBIOSHandoff, KernelHandoff
};

pub use protocols::ipc::{
    SecureChannel, ChannelConfiguration, MessageProtocol,
    IPCMessage, ChannelSecurity, IsolatedCommunication
};

// Configuration management exports
pub use utils::configuration::{
    SystemConfiguration, SecurityConfiguration,
    ConfigurationLoader, ConfigurationValidator, ConfigurationManager
};
