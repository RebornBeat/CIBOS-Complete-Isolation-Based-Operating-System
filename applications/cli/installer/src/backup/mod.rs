// BACKUP MODULE - cibos/applications/cli/installer/src/backup/mod.rs
pub mod backup {
    //! Backup and recovery management for installation safety
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{fs, time::Duration};
    use uuid::Uuid;
    use std::sync::Arc;
    use std::path::PathBuf;
    use chrono::{DateTime, Utc};

    // Backup component exports
    pub use self::manager::{BackupManager, BackupCoordinator, BackupExecutor};
    pub use self::recovery::{RecoveryManager, RecoveryCoordinator, RecoveryExecutor};
    pub use self::firmware::{FirmwareBackup, FirmwareRestore, FirmwareArchive};
    pub use self::system::{SystemBackup, SystemRestore, SystemArchive};

    // Backup module declarations
    pub mod manager;
    pub mod recovery;
    pub mod firmware;
    pub mod system;

    /// Comprehensive backup manager for system protection
    #[derive(Debug)]
    pub struct BackupManager {
        pub coordinator: BackupCoordinator,
        pub executor: BackupExecutor,
        pub recovery: RecoveryManager,
        pub system_access: Arc<SystemAccess>,
    }

    /// Backup configuration for system protection parameters
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BackupConfiguration {
        pub create_backup: bool,
        pub backup_compression: bool,
        pub verify_backup_integrity: bool,
        pub configure_recovery: bool,
        pub backup_retention_days: u32,
    }

    /// Recovery configuration for system restoration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecoveryConfiguration {
        pub recovery_mode: RecoveryMode,
        pub network_enabled: bool,
        pub full_system_tools: bool,
        pub automatic_detection: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum RecoveryMode {
        Full,
        Minimal,
        Network,
    }

    impl RecoveryConfiguration {
        pub fn full_recovery() -> Self {
            Self {
                recovery_mode: RecoveryMode::Full,
                network_enabled: true,
                full_system_tools: true,
                automatic_detection: true,
            }
        }

        pub fn minimal_recovery() -> Self {
            Self {
                recovery_mode: RecoveryMode::Minimal,
                network_enabled: false,
                full_system_tools: false,
                automatic_detection: true,
            }
        }

        pub fn network_recovery() -> Self {
            Self {
                recovery_mode: RecoveryMode::Network,
                network_enabled: true,
                full_system_tools: false,
                automatic_detection: true,
            }
        }
    }

    use shared::types::hardware::SystemAccess;
}
