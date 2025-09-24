// cibos/applications/cli/file_manager/src/operations/mod.rs
pub mod operations {
    //! File operation management with complete isolation enforcement
    //!
    //! This module provides comprehensive file operation capabilities while
    //! maintaining mathematical isolation boundaries. All file operations
    //! are validated through the isolation manager and executed within
    //! authorized path boundaries only.

    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, time::{Duration, Instant}};
    use uuid::Uuid;
    use chrono::{DateTime, Utc};
    use std::sync::Arc;
    use std::path::{Path, PathBuf};
    use std::collections::HashMap;

    // Component exports for file operations
    pub use self::manager::{FileOperationManager, OperationQueue, OperationExecutor};
    pub use self::operations::{FileOperation, OperationType, OperationParameters, OperationMetadata};
    pub use self::progress::{OperationProgress, ProgressTracker, ProgressCallback};
    pub use self::results::{OperationResult, OperationStatus, OperationError, OperationStatistics};
    pub use self::validation::{OperationValidator, ValidationResult, ValidationError};

    // Internal component modules
    pub mod manager;
    pub mod operations;
    pub mod progress;
    pub mod results;
    pub mod validation;

    /// File operation manager coordinating all file operations
    #[derive(Debug)]
    pub struct FileOperationManager {
        pub operation_queue: Arc<OperationQueue>,
        pub progress_tracker: Arc<ProgressTracker>,
        pub operation_validator: Arc<OperationValidator>,
        pub isolation_enforcer: Arc<super::isolation::IsolationBoundaryManager>,
    }

    /// File operation types with isolation boundary enforcement
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum FileOperation {
        Copy {
            source: PathBuf,
            destination: PathBuf,
            recursive: bool,
            preserve_permissions: bool,
            isolation_boundary: Uuid,
        },
        Move {
            source: PathBuf,
            destination: PathBuf,
            isolation_boundary: Uuid,
        },
        Delete {
            target: PathBuf,
            recursive: bool,
            secure_delete: bool,
            isolation_boundary: Uuid,
        },
        CreateDirectory {
            path: PathBuf,
            permissions: super::FilePermissions,
            isolation_boundary: Uuid,
        },
        ListDirectory {
            path: PathBuf,
            detailed: bool,
            recursive: bool,
            isolation_boundary: Uuid,
        },
        ReadFile {
            path: PathBuf,
            offset: Option<u64>,
            length: Option<u64>,
            isolation_boundary: Uuid,
        },
        WriteFile {
            path: PathBuf,
            data: Vec<u8>,
            append_mode: bool,
            isolation_boundary: Uuid,
        },
    }

    /// Operation result with detailed execution information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationResult {
        pub operation_id: Uuid,
        pub success: bool,
        pub execution_time: Duration,
        pub bytes_processed: u64,
        pub files_processed: u32,
        pub error_message: Option<String>,
        pub operation_statistics: OperationStatistics,
    }

    /// Operation execution statistics
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationStatistics {
        pub start_time: DateTime<Utc>,
        pub end_time: Option<DateTime<Utc>>,
        pub peak_memory_usage: u64,
        pub io_operations_count: u64,
        pub validation_checks_performed: u32,
    }
}

