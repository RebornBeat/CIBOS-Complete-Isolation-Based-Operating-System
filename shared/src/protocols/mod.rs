// SHARED PROTOCOLS MODULE ORGANIZATION - shared/src/protocols/mod.rs
pub mod shared_protocols {
    //! Communication protocols for inter-component coordination
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    use std::sync::Arc;
    use std::collections::HashMap;
    
    // Protocol component exports
    pub use self::handoff::{HandoffProtocol, HandoffData, CIBIOSHandoff, KernelHandoff};
    pub use self::ipc::{SecureChannel, ChannelConfiguration, MessageProtocol, IPCMessage};
    pub use self::authentication::{AuthenticationProtocol, CredentialProtocol, VerificationProtocol};
    pub use self::isolation::{IsolationProtocol, BoundaryProtocol, EnforcementProtocol};
    
    // Protocol module declarations
    pub mod handoff;
    pub mod ipc;
    pub mod authentication;
    pub mod isolation;
    
    /// Handoff protocol for CIBIOS to CIBOS transfer
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HandoffProtocol {
        pub handoff_id: Uuid,
        pub cibios_version: String,
        pub hardware_config: shared::types::hardware::HardwareConfiguration,
        pub isolation_boundaries: shared::types::isolation::BoundaryConfiguration,
        pub verification_chain: Vec<VerificationResult>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VerificationResult {
        pub component_name: String,
        pub verification_passed: bool,
        pub signature_valid: bool,
        pub integrity_hash: String,
    }
}
