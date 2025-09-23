// VERIFICATION MODULE - cibos/applications/cli/installer/src/verification/mod.rs
pub mod verification {
    //! Installation verification and integrity checking
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::time::Duration;
    use uuid::Uuid;
    use std::sync::Arc;
    use chrono::{DateTime, Utc};

    // Verification component exports
    pub use self::engine::{VerificationEngine, VerificationCoordinator, VerificationExecutor};
    pub use self::integrity::{IntegrityChecker, ComponentVerifier, SystemVerifier};
    pub use self::signature::{SignatureVerifier, CryptographicVerifier, CertificateValidator};
    pub use self::result::{VerificationResult, VerificationStatus, VerificationReport};

    // Verification module declarations
    pub mod engine;
    pub mod integrity;
    pub mod signature;
    pub mod result;

    /// Comprehensive verification engine for installation validation
    #[derive(Debug)]
    pub struct VerificationEngine {
        pub coordinator: VerificationCoordinator,
        pub integrity_checker: IntegrityChecker,
        pub signature_verifier: SignatureVerifier,
    }

    /// Verification result encompassing all validation checks
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VerificationResult {
        pub verification_id: Uuid,
        pub all_checks_passed: bool,
        pub firmware_valid: bool,
        pub os_valid: bool,
        pub recovery_available: bool,
        pub hardware_profile: super::hardware::HardwareProfile,
        pub verification_timestamp: DateTime<Utc>,
        pub detailed_report: VerificationReport,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VerificationReport {
        pub signature_verification: bool,
        pub integrity_verification: bool,
        pub compatibility_verification: bool,
        pub performance_metrics: VerificationMetrics,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VerificationMetrics {
        pub verification_duration: Duration,
        pub components_verified: u32,
        pub errors_detected: u32,
        pub warnings_generated: u32,
    }
}

