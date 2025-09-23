// INSTALLATION MODULE - cibos/applications/cli/installer/src/installation/mod.rs
pub mod installation {
    //! Installation engine for CLI installer operations
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{fs, process::Command, time::Duration};
    use uuid::Uuid;
    use std::sync::Arc;
    use std::path::PathBuf;
    use chrono::{DateTime, Utc};

    // Installation component exports
    pub use self::engine::{InstallationEngine, InstallationCoordinator, InstallationExecutor};
    pub use self::process::{InstallationProcess, InstallationStep, InstallationPhase};
    pub use self::config::{InstallationConfiguration, DeploymentConfiguration, PlatformConfiguration};
    pub use self::progress::{InstallationProgress, ProgressTracker, ProgressUpdate};
    pub use self::result::{InstallationResult, InstallationStatus, InstallationMetrics};

    // Installation module declarations
    pub mod engine;
    pub mod process;
    pub mod config;
    pub mod progress;
    pub mod result;

    /// Main installation engine coordinating all installation operations
    #[derive(Debug)]
    pub struct InstallationEngine {
        pub coordinator: InstallationCoordinator,
        pub executor: InstallationExecutor,
        pub progress_tracker: Arc<ProgressTracker>,
        pub system_access: Arc<SystemAccess>,
    }

    /// Installation configuration for CLI environments
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InstallationConfiguration {
        pub target_platform: shared::types::hardware::HardwarePlatform,
        pub verify_before_install: bool,
        pub create_recovery_partition: bool,
        pub automated_installation: bool,
        pub installation_timeout: Duration,
    }

    /// Installation progress tracking for user feedback
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InstallationProgress {
        pub current_phase: InstallationPhase,
        pub phase_progress: f32,
        pub overall_progress: f32,
        pub estimated_time_remaining: Option<Duration>,
        pub current_operation: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum InstallationPhase {
        Preparation,
        Backup,
        FirmwareInstallation,
        OSInstallation,
        Verification,
        RecoverySetup,
        Completion,
    }

    use shared::types::hardware::SystemAccess;
}

