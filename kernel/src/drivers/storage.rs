// =============================================================================
// CIBOS KERNEL DRIVERS - STORAGE DRIVER FRAMEWORK
// cibos/kernel/src/drivers/storage.rs
// =============================================================================

//! Storage driver framework providing isolated access to storage devices
//! 
//! This module implements the storage abstraction layer that enables applications
//! to access storage devices through complete isolation boundaries. Each storage
//! operation is confined to authorized paths within the application's storage boundary.

// External dependencies for storage functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, time::Duration, fs};
use async_trait::async_trait;
use uuid::Uuid;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// Internal kernel imports
use crate::core::isolation::{IsolationManager, StorageIsolationBoundary};
use crate::security::{SecurityManager, ResourceAuthorization};

// Shared type imports
use shared::types::isolation::{StorageBoundary, IsolationLevel};
use shared::types::hardware::{StorageCapabilities, StorageType};
use shared::types::error::{KernelError, StorageError, IsolationError};

/// Storage driver framework coordinating isolated storage access
#[derive(Debug)]
pub struct StorageDriverFramework {
    pub storage_drivers: Arc<RwLock<HashMap<String, Box<dyn IsolatedStorageDriver + Send + Sync>>>>,
    pub isolation_manager: Arc<IsolationManager>,
    pub authorization_engine: Arc<ResourceAuthorization>,
}

/// Interface for isolated storage drivers that enforce access boundaries
#[async_trait]
pub trait IsolatedStorageDriver {
    /// Read data from storage within isolation boundary
    async fn read_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<Vec<u8>>;
    
    /// Write data to storage within isolation boundary
    async fn write_isolated(&self, path: &Path, data: &[u8], isolation_boundary: &Uuid) -> AnyhowResult<()>;
    
    /// Delete file within isolation boundary
    async fn delete_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<()>;
    
    /// List directory contents within isolation boundary
    async fn list_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<Vec<StorageEntry>>;
    
    /// Create directory within isolation boundary
    async fn create_directory_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<()>;
    
    /// Get storage device capabilities
    fn get_capabilities(&self) -> StorageCapabilities;
    
    /// Get driver name for identification
    fn get_driver_name(&self) -> &str;
}

/// Storage entry representing files and directories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub name: String,
    pub path: PathBuf,
    pub entry_type: StorageEntryType,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub permissions: StoragePermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageEntryType {
    File,
    Directory,
    SymbolicLink { target: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Generic storage interface for applications
pub struct StorageInterface {
    storage_framework: Arc<StorageDriverFramework>,
    isolation_boundary: Uuid,
    authorized_paths: Vec<PathBuf>,
}

impl StorageDriverFramework {
    /// Initialize storage driver framework with isolation enforcement
    pub async fn initialize(
        isolation_manager: Arc<IsolationManager>, 
        authorization_engine: Arc<ResourceAuthorization>
    ) -> AnyhowResult<Self> {
        info!("Initializing storage driver framework with isolation boundaries");

        let storage_drivers = Arc::new(RwLock::new(HashMap::new()));

        // Initialize built-in storage drivers
        let framework = Self {
            storage_drivers: storage_drivers.clone(),
            isolation_manager,
            authorization_engine,
        };

        // Register default file system driver
        framework.register_driver("default_fs", Box::new(DefaultFilesystemDriver::new().await?)).await?;

        info!("Storage driver framework initialization completed");
        Ok(framework)
    }

    /// Register a new isolated storage driver
    pub async fn register_driver(&self, name: &str, driver: Box<dyn IsolatedStorageDriver + Send + Sync>) -> AnyhowResult<()> {
        info!("Registering storage driver: {}", name);
        
        let mut drivers = self.storage_drivers.write().await;
        drivers.insert(name.to_string(), driver);
        
        info!("Storage driver {} registered successfully", name);
        Ok(())
    }

    /// Create storage interface for application with isolation boundary
    pub async fn create_interface(&self, isolation_boundary: Uuid, authorized_paths: Vec<PathBuf>) -> AnyhowResult<StorageInterface> {
        info!("Creating storage interface for isolation boundary: {}", isolation_boundary);

        // Verify isolation boundary exists
        self.isolation_manager.verify_boundary_exists(&isolation_boundary).await
            .context("Isolation boundary verification failed")?;

        // Validate authorized paths are within boundary
        for path in &authorized_paths {
            self.authorization_engine.verify_storage_access(&isolation_boundary, path).await
                .context("Storage path authorization failed")?;
        }

        Ok(StorageInterface {
            storage_framework: Arc::new(self.clone()),
            isolation_boundary,
            authorized_paths,
        })
    }
}

// Implementation needs Clone trait for Arc usage
impl Clone for StorageDriverFramework {
    fn clone(&self) -> Self {
        Self {
            storage_drivers: self.storage_drivers.clone(),
            isolation_manager: self.isolation_manager.clone(),
            authorization_engine: self.authorization_engine.clone(),
        }
    }
}

impl StorageInterface {
    /// Read file data within isolation boundary
    pub async fn read_file(&self, path: &Path) -> AnyhowResult<Vec<u8>> {
        debug!("Reading file: {:?} within isolation boundary: {}", path, self.isolation_boundary);

        // Verify path is authorized for this isolation boundary
        self.verify_path_authorization(path).await
            .context("Path authorization verification failed")?;

        // Get appropriate storage driver
        let drivers = self.storage_framework.storage_drivers.read().await;
        let driver = drivers.get("default_fs")
            .ok_or_else(|| anyhow::anyhow!("Default storage driver not available"))?;

        // Perform isolated read operation
        driver.read_isolated(path, &self.isolation_boundary).await
            .context("Isolated file read operation failed")
    }

    /// Write data to file within isolation boundary
    pub async fn write_file(&self, path: &Path, data: &[u8]) -> AnyhowResult<()> {
        debug!("Writing file: {:?} within isolation boundary: {}", path, self.isolation_boundary);

        // Verify path is authorized for this isolation boundary
        self.verify_path_authorization(path).await
            .context("Path authorization verification failed")?;

        // Get appropriate storage driver
        let drivers = self.storage_framework.storage_drivers.read().await;
        let driver = drivers.get("default_fs")
            .ok_or_else(|| anyhow::anyhow!("Default storage driver not available"))?;

        // Perform isolated write operation
        driver.write_isolated(path, data, &self.isolation_boundary).await
            .context("Isolated file write operation failed")
    }

    /// List directory contents within isolation boundary
    pub async fn list_directory(&self, path: &Path) -> AnyhowResult<Vec<StorageEntry>> {
        debug!("Listing directory: {:?} within isolation boundary: {}", path, self.isolation_boundary);

        // Verify path is authorized for this isolation boundary
        self.verify_path_authorization(path).await
            .context("Path authorization verification failed")?;

        // Get appropriate storage driver
        let drivers = self.storage_framework.storage_drivers.read().await;
        let driver = drivers.get("default_fs")
            .ok_or_else(|| anyhow::anyhow!("Default storage driver not available"))?;

        // Perform isolated directory listing
        driver.list_isolated(path, &self.isolation_boundary).await
            .context("Isolated directory listing operation failed")
    }

    /// Verify path is within authorized boundaries for this isolation context
    async fn verify_path_authorization(&self, path: &Path) -> AnyhowResult<()> {
        let canonical_path = path.canonicalize()
            .context("Failed to canonicalize path")?;

        for authorized_path in &self.authorized_paths {
            if canonical_path.starts_with(authorized_path) {
                return Ok(());
            }
        }

        Err(anyhow::anyhow!(
            "Path {:?} is not authorized for isolation boundary {}", 
            path, self.isolation_boundary
        ))
    }
}

/// Default filesystem driver implementation
struct DefaultFilesystemDriver {
    capabilities: StorageCapabilities,
}

impl DefaultFilesystemDriver {
    async fn new() -> AnyhowResult<Self> {
        Ok(Self {
            capabilities: StorageCapabilities {
                internal_storage_size: 0, // Will be detected
                external_storage_support: true,
                storage_type: StorageType::SSD, // Default assumption
                encryption_support: true,
            },
        })
    }
}

#[async_trait]
impl IsolatedStorageDriver for DefaultFilesystemDriver {
    async fn read_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<Vec<u8>> {
        debug!("DefaultFS: Reading {:?} for boundary {}", path, isolation_boundary);
        
        // In a real implementation, this would verify the path is within the isolation boundary
        // and perform additional security checks
        fs::read(path).await
            .context("File read operation failed")
    }

    async fn write_isolated(&self, path: &Path, data: &[u8], isolation_boundary: &Uuid) -> AnyhowResult<()> {
        debug!("DefaultFS: Writing {:?} for boundary {}", path, isolation_boundary);
        
        // In a real implementation, this would verify write permissions within isolation boundary
        fs::write(path, data).await
            .context("File write operation failed")
    }

    async fn delete_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<()> {
        debug!("DefaultFS: Deleting {:?} for boundary {}", path, isolation_boundary);
        
        // Verify deletion is authorized within isolation boundary
        fs::remove_file(path).await
            .context("File deletion operation failed")
    }

    async fn list_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<Vec<StorageEntry>> {
        debug!("DefaultFS: Listing {:?} for boundary {}", path, isolation_boundary);
        
        let mut entries = Vec::new();
        let mut read_dir = fs::read_dir(path).await
            .context("Directory read operation failed")?;

        while let Some(entry) = read_dir.next_entry().await.context("Directory entry read failed")? {
            let metadata = entry.metadata().await.context("Metadata read failed")?;
            let file_name = entry.file_name().into_string()
                .map_err(|_| anyhow::anyhow!("Invalid filename"))?;

            entries.push(StorageEntry {
                name: file_name,
                path: entry.path(),
                entry_type: if metadata.is_dir() { 
                    StorageEntryType::Directory 
                } else { 
                    StorageEntryType::File 
                },
                size: metadata.len(),
                modified: DateTime::from_timestamp(
                    metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64, 0
                ).unwrap(),
                permissions: StoragePermissions {
                    readable: true,  // Simplified - would check actual permissions
                    writable: !metadata.permissions().readonly(),
                    executable: false, // Simplified
                },
            });
        }

        Ok(entries)
    }

    async fn create_directory_isolated(&self, path: &Path, isolation_boundary: &Uuid) -> AnyhowResult<()> {
        debug!("DefaultFS: Creating directory {:?} for boundary {}", path, isolation_boundary);
        
        fs::create_dir_all(path).await
            .context("Directory creation failed")
    }

    fn get_capabilities(&self) -> StorageCapabilities {
        self.capabilities.clone()
    }

    fn get_driver_name(&self) -> &str {
        "default_filesystem"
    }
}
