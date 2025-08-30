// Desktop File Manager Module Organization - cibos/applications/desktop/file_manager/src/file_operations/mod.rs
pub mod file_operations {
    //! File operation management with isolation enforcement
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{fs, time::Duration};
    use uuid::Uuid;
    use std::path::PathBuf;
    use std::sync::Arc;
    use chrono::{DateTime, Utc};
    
    // File operation component exports
    pub use self::manager::{FileOperationManager, OperationQueue, OperationScheduler};
    pub use self::operations::{FileOperation, OperationType, OperationParameters};
    pub use self::progress::{OperationProgress, ProgressTracker, ProgressUpdate};
    pub use self::results::{OperationResult, OperationStatus, OperationError};
    
    // File operation module declarations
    pub mod manager;
    pub mod operations;
    pub mod progress;
    pub mod results;
    
    /// File operation management with isolation boundaries
    #[derive(Debug)]
    pub struct FileOperationManager {
        pub operation_queue: Arc<OperationQueue>,
        pub progress_tracker: Arc<ProgressTracker>,
        pub isolation_enforcer: Arc<FileOperationIsolation>,
    }
    
    #[derive(Debug)]
    pub struct FileOperationIsolation {
        pub operation_boundaries: std::collections::HashMap<Uuid, OperationBoundary>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationBoundary {
        pub operation_id: Uuid,
        pub allowed_source_paths: Vec<PathBuf>,
        pub allowed_destination_paths: Vec<PathBuf>,
        pub isolation_level: shared::types::isolation::IsolationLevel,
    }
    
    /// File operation types with isolation enforcement
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum FileOperation {
        Copy {
            source: PathBuf,
            destination: PathBuf,
            preserve_permissions: bool,
        },
        Move {
            source: PathBuf,
            destination: PathBuf,
        },
        Delete {
            target: PathBuf,
            secure_delete: bool,
        },
        CreateDirectory {
            path: PathBuf,
            permissions: DirectoryPermissions,
        },
        Rename {
            old_path: PathBuf,
            new_path: PathBuf,
        },
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DirectoryPermissions {
        pub owner_read: bool,
        pub owner_write: bool,
        pub owner_execute: bool,
        pub group_read: bool,
        pub group_write: bool,
        pub group_execute: bool,
        pub other_read: bool,
        pub other_write: bool,
        pub other_execute: bool,
    }
}
