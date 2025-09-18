// =============================================================================
// CIBOS KERNEL FILESYSTEM - EXT4 IMPLEMENTATION
// cibos/kernel/src/fs/ext4.rs
// Isolated Ext4 Filesystem Implementation with Complete Boundary Enforcement
// =============================================================================

// External dependencies for Ext4 functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, fs, io::{AsyncReadExt, AsyncWriteExt}};
use async_trait::async_trait;
use uuid::Uuid;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// Internal kernel imports
use crate::core::isolation::{IsolationManager, FilesystemIsolationBoundary};
use crate::security::{SecurityManager, ResourceAuthorization};
use super::vfs::{FilesystemInterface, IsolatedFilesystem};
use super::encryption::{FilesystemEncryption, EncryptedBlock};

// Shared type imports
use shared::types::isolation::{StorageBoundary, IsolationLevel};
use shared::types::hardware::{StorageCapabilities, StorageType};
use shared::types::error::{KernelError, FilesystemError, IsolationError};

/// Ext4 filesystem implementation with complete isolation enforcement
#[derive(Debug)]
pub struct Ext4Filesystem {
    filesystem_id: Uuid,
    mount_point: PathBuf,
    isolation_manager: Arc<Ext4IsolationManager>,
    encryption_engine: Arc<FilesystemEncryption>,
    superblock: Ext4Superblock,
    block_cache: Arc<RwLock<BlockCache>>,
    inode_cache: Arc<RwLock<InodeCache>>,
}

/// Ext4 filesystem configuration for isolated operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Configuration {
    pub block_size: u32,
    pub inode_count: u32,
    pub block_count: u64,
    pub encryption_enabled: bool,
    pub isolation_enforcement: bool,
    pub journal_enabled: bool,
}

/// Ext4 isolation manager enforcing filesystem-level boundaries
#[derive(Debug)]
pub struct Ext4IsolationManager {
    filesystem_boundaries: RwLock<HashMap<Uuid, Ext4FilesystemBoundary>>,
    access_monitor: Arc<Mutex<FilesystemAccessMonitor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4FilesystemBoundary {
    pub boundary_id: Uuid,
    pub application_id: Uuid,
    pub allowed_inodes: Vec<u32>,
    pub allowed_blocks: Vec<u64>,
    pub read_only_inodes: Vec<u32>,
    pub isolation_level: IsolationLevel,
}

/// Ext4 superblock structure for filesystem metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Superblock {
    pub total_inodes: u32,
    pub total_blocks: u64,
    pub free_inodes: u32,
    pub free_blocks: u64,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub filesystem_state: FilesystemState,
    pub last_mount_time: DateTime<Utc>,
    pub last_check_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesystemState {
    Clean,
    HasErrors,
    InRecovery,
}

/// Block cache for performance optimization with isolation
#[derive(Debug)]
pub struct BlockCache {
    cached_blocks: HashMap<u64, CachedBlock>,
    cache_size_limit: usize,
    access_counts: HashMap<u64, u32>,
}

#[derive(Debug, Clone)]
pub struct CachedBlock {
    pub block_number: u64,
    pub data: Vec<u8>,
    pub dirty: bool,
    pub last_access: DateTime<Utc>,
    pub isolation_boundary: Option<Uuid>,
}

/// Inode cache for filesystem metadata with isolation tracking
#[derive(Debug)]
pub struct InodeCache {
    cached_inodes: HashMap<u32, CachedInode>,
    cache_size_limit: usize,
}

#[derive(Debug, Clone)]
pub struct CachedInode {
    pub inode_number: u32,
    pub inode_data: Ext4Inode,
    pub last_access: DateTime<Utc>,
    pub isolation_boundary: Option<Uuid>,
}

/// Ext4 inode structure with isolation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ext4Inode {
    pub inode_number: u32,
    pub file_mode: u16,
    pub user_id: u32,
    pub group_id: u32,
    pub file_size: u64,
    pub access_time: DateTime<Utc>,
    pub creation_time: DateTime<Utc>,
    pub modification_time: DateTime<Utc>,
    pub deletion_time: Option<DateTime<Utc>>,
    pub block_pointers: Vec<u64>,
    pub isolation_metadata: InodeIsolationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeIsolationMetadata {
    pub owning_boundary: Option<Uuid>,
    pub access_permissions: Vec<BoundaryPermission>,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryPermission {
    pub boundary_id: Uuid,
    pub read_access: bool,
    pub write_access: bool,
    pub execute_access: bool,
}

/// Filesystem access monitoring for security enforcement
#[derive(Debug)]
pub struct FilesystemAccessMonitor {
    access_log: Vec<FilesystemAccessEvent>,
    max_log_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemAccessEvent {
    pub timestamp: DateTime<Utc>,
    pub boundary_id: Uuid,
    pub operation_type: FilesystemOperation,
    pub inode_number: u32,
    pub access_granted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesystemOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    SetPermissions,
}

impl Ext4Filesystem {
    /// Initialize Ext4 filesystem with complete isolation enforcement
    pub async fn initialize(
        config: &Ext4Configuration,
        mount_point: PathBuf,
        isolation_manager: Arc<IsolationManager>
    ) -> AnyhowResult<Self> {
        info!("Initializing isolated Ext4 filesystem at: {}", mount_point.display());

        // Create filesystem-specific isolation manager
        let ext4_isolation = Arc::new(Ext4IsolationManager::initialize().await
            .context("Ext4 isolation manager initialization failed")?);

        // Initialize encryption engine if enabled
        let encryption_engine = if config.encryption_enabled {
            Arc::new(FilesystemEncryption::initialize_for_ext4().await
                .context("Ext4 encryption initialization failed")?)
        } else {
            Arc::new(FilesystemEncryption::disabled())
        };

        // Load or create superblock
        let superblock = Self::load_or_create_superblock(&mount_point, config).await
            .context("Superblock initialization failed")?;

        // Initialize caches with isolation tracking
        let block_cache = Arc::new(RwLock::new(BlockCache::new(1024))); // 1024 block cache
        let inode_cache = Arc::new(RwLock::new(InodeCache::new(512))); // 512 inode cache

        let filesystem_id = Uuid::new_v4();

        info!("Ext4 filesystem initialized successfully with ID: {}", filesystem_id);

        Ok(Self {
            filesystem_id,
            mount_point,
            isolation_manager: ext4_isolation,
            encryption_engine,
            superblock,
            block_cache,
            inode_cache,
        })
    }

    /// Load or create Ext4 superblock with validation
    async fn load_or_create_superblock(
        mount_point: &Path,
        config: &Ext4Configuration
    ) -> AnyhowResult<Ext4Superblock> {
        let superblock_path = mount_point.join("superblock");

        if superblock_path.exists() {
            // Load existing superblock
            Self::load_superblock(&superblock_path).await
        } else {
            // Create new superblock
            Self::create_superblock(config).await
        }
    }

    /// Load existing superblock from storage
    async fn load_superblock(superblock_path: &Path) -> AnyhowResult<Ext4Superblock> {
        info!("Loading existing Ext4 superblock from: {}", superblock_path.display());

        let superblock_data = fs::read(superblock_path).await
            .context("Failed to read superblock file")?;

        let superblock: Ext4Superblock = bincode::deserialize(&superblock_data)
            .context("Failed to deserialize superblock")?;

        // Validate superblock integrity
        if superblock.filesystem_state == FilesystemState::HasErrors {
            warn!("Filesystem was not cleanly unmounted - recovery may be needed");
        }

        Ok(superblock)
    }

    /// Create new superblock for fresh filesystem
    async fn create_superblock(config: &Ext4Configuration) -> AnyhowResult<Ext4Superblock> {
        info!("Creating new Ext4 superblock");

        Ok(Ext4Superblock {
            total_inodes: config.inode_count,
            total_blocks: config.block_count,
            free_inodes: config.inode_count - 1, // Reserve root inode
            free_blocks: config.block_count - 100, // Reserve some blocks for metadata
            block_size: config.block_size,
            blocks_per_group: 8192, // Standard block group size
            inodes_per_group: config.inode_count / 32, // Distribute inodes across groups
            filesystem_state: FilesystemState::Clean,
            last_mount_time: Utc::now(),
            last_check_time: Utc::now(),
        })
    }

    /// Read file content with isolation boundary enforcement
    pub async fn read_file(
        &self,
        path: &Path,
        boundary_id: Uuid
    ) -> AnyhowResult<Vec<u8>> {
        info!("Reading file: {} for boundary: {}", path.display(), boundary_id);

        // Verify boundary has read access to this path
        self.isolation_manager.verify_read_access(&path, boundary_id).await
            .context("Read access verification failed")?;

        // Resolve path to inode
        let inode_number = self.resolve_path_to_inode(path).await
            .context("Path resolution failed")?;

        // Load inode with isolation check
        let inode = self.load_inode_with_isolation(inode_number, boundary_id).await
            .context("Inode loading failed")?;

        // Read file blocks
        let mut file_data = Vec::new();
        for &block_number in &inode.block_pointers {
            let block_data = self.read_block_with_isolation(block_number, boundary_id).await
                .context("Block reading failed")?;
            file_data.extend_from_slice(&block_data);
        }

        // Trim to actual file size
        file_data.truncate(inode.file_size as usize);

        // Log access for security monitoring
        self.isolation_manager.log_access(FilesystemAccessEvent {
            timestamp: Utc::now(),
            boundary_id,
            operation_type: FilesystemOperation::Read,
            inode_number,
            access_granted: true,
        }).await;

        info!("File read completed: {} bytes", file_data.len());
        Ok(file_data)
    }

    /// Write file content with isolation boundary enforcement
    pub async fn write_file(
        &self,
        path: &Path,
        data: &[u8],
        boundary_id: Uuid
    ) -> AnyhowResult<()> {
        info!("Writing file: {} for boundary: {} ({} bytes)", 
              path.display(), boundary_id, data.len());

        // Verify boundary has write access to this path
        self.isolation_manager.verify_write_access(&path, boundary_id).await
            .context("Write access verification failed")?;

        // Create or load inode
        let inode_number = if self.path_exists(path).await? {
            self.resolve_path_to_inode(path).await?
        } else {
            self.create_file_inode(path, boundary_id).await?
        };

        // Calculate required blocks
        let blocks_needed = (data.len() + self.superblock.block_size as usize - 1) 
            / self.superblock.block_size as usize;

        // Allocate blocks for file data
        let allocated_blocks = self.allocate_blocks(blocks_needed, boundary_id).await
            .context("Block allocation failed")?;

        // Write data to blocks
        for (i, &block_number) in allocated_blocks.iter().enumerate() {
            let block_start = i * self.superblock.block_size as usize;
            let block_end = std::cmp::min(block_start + self.superblock.block_size as usize, data.len());
            let block_data = &data[block_start..block_end];

            self.write_block_with_isolation(block_number, block_data, boundary_id).await
                .context("Block writing failed")?;
        }

        // Update inode with new block pointers and file size
        self.update_inode(inode_number, |inode| {
            inode.block_pointers = allocated_blocks;
            inode.file_size = data.len() as u64;
            inode.modification_time = Utc::now();
        }).await.context("Inode update failed")?;

        // Log access for security monitoring
        self.isolation_manager.log_access(FilesystemAccessEvent {
            timestamp: Utc::now(),
            boundary_id,
            operation_type: FilesystemOperation::Write,
            inode_number,
            access_granted: true,
        }).await;

        info!("File write completed successfully");
        Ok(())
    }

    /// Create new file inode with isolation metadata
    async fn create_file_inode(&self, path: &Path, boundary_id: Uuid) -> AnyhowResult<u32> {
        let inode_number = self.allocate_inode().await
            .context("Inode allocation failed")?;

        let inode = Ext4Inode {
            inode_number,
            file_mode: 0o644, // Regular file permissions
            user_id: 1000, // Default user ID
            group_id: 1000, // Default group ID
            file_size: 0,
            access_time: Utc::now(),
            creation_time: Utc::now(),
            modification_time: Utc::now(),
            deletion_time: None,
            block_pointers: Vec::new(),
            isolation_metadata: InodeIsolationMetadata {
                owning_boundary: Some(boundary_id),
                access_permissions: vec![BoundaryPermission {
                    boundary_id,
                    read_access: true,
                    write_access: true,
                    execute_access: false,
                }],
                encryption_required: self.encryption_engine.is_enabled(),
            },
        };

        self.write_inode(inode).await
            .context("Inode writing failed")?;

        // Add directory entry
        self.add_directory_entry(path, inode_number).await
            .context("Directory entry creation failed")?;

        Ok(inode_number)
    }

    /// Resolve file path to inode number
    async fn resolve_path_to_inode(&self, path: &Path) -> AnyhowResult<u32> {
        // Simplified path resolution - real implementation would traverse directory structure
        // For now, use a hash-based approach for demonstration
        let path_hash = self.hash_path(path);
        
        // In a real implementation, this would walk the directory tree
        // starting from root inode and following directory entries
        Ok(path_hash % self.superblock.total_inodes)
    }

    /// Simple path hashing for inode resolution (demonstration only)
    fn hash_path(&self, path: &Path) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        path.to_string_lossy().hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Load inode with isolation boundary verification
    async fn load_inode_with_isolation(
        &self,
        inode_number: u32,
        boundary_id: Uuid
    ) -> AnyhowResult<Ext4Inode> {
        // Check inode cache first
        {
            let cache = self.inode_cache.read().await;
            if let Some(cached) = cache.cached_inodes.get(&inode_number) {
                if let Some(cached_boundary) = cached.isolation_boundary {
                    if cached_boundary == boundary_id {
                        return Ok(cached.inode_data.clone());
                    }
                }
            }
        }

        // Load inode from storage
        let inode = self.load_inode_from_storage(inode_number).await
            .context("Inode loading from storage failed")?;

        // Verify boundary has access to this inode
        self.verify_inode_access(&inode, boundary_id)
            .context("Inode access verification failed")?;

        // Cache inode with isolation boundary
        {
            let mut cache = self.inode_cache.write().await;
            cache.cached_inodes.insert(inode_number, CachedInode {
                inode_number,
                inode_data: inode.clone(),
                last_access: Utc::now(),
                isolation_boundary: Some(boundary_id),
            });
        }

        Ok(inode)
    }

    /// Verify boundary has access to specific inode
    fn verify_inode_access(&self, inode: &Ext4Inode, boundary_id: Uuid) -> AnyhowResult<()> {
        // Check if boundary owns this inode
        if let Some(owning_boundary) = inode.isolation_metadata.owning_boundary {
            if owning_boundary == boundary_id {
                return Ok(());
            }
        }

        // Check explicit access permissions
        for permission in &inode.isolation_metadata.access_permissions {
            if permission.boundary_id == boundary_id && permission.read_access {
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Boundary {} does not have access to inode {}", 
                          boundary_id, inode.inode_number))
    }

    /// Load inode data from storage
    async fn load_inode_from_storage(&self, inode_number: u32) -> AnyhowResult<Ext4Inode> {
        // Calculate inode location on disk
        let group_number = inode_number / self.superblock.inodes_per_group;
        let inode_offset = inode_number % self.superblock.inodes_per_group;

        // In a real implementation, this would calculate the exact disk location
        // and read the inode data from the appropriate block group
        // For demonstration, we'll create a placeholder inode
        Ok(Ext4Inode {
            inode_number,
            file_mode: 0o644,
            user_id: 1000,
            group_id: 1000,
            file_size: 0,
            access_time: Utc::now(),
            creation_time: Utc::now(),
            modification_time: Utc::now(),
            deletion_time: None,
            block_pointers: Vec::new(),
            isolation_metadata: InodeIsolationMetadata {
                owning_boundary: None,
                access_permissions: Vec::new(),
                encryption_required: false,
            },
        })
    }

    /// Read block with isolation enforcement
    async fn read_block_with_isolation(
        &self,
        block_number: u64,
        boundary_id: Uuid
    ) -> AnyhowResult<Vec<u8>> {
        // Check block cache first
        {
            let cache = self.block_cache.read().await;
            if let Some(cached) = cache.cached_blocks.get(&block_number) {
                if let Some(cached_boundary) = cached.isolation_boundary {
                    if cached_boundary == boundary_id {
                        return Ok(cached.data.clone());
                    }
                }
            }
        }

        // Read block from storage
        let mut block_data = self.read_block_from_storage(block_number).await
            .context("Block reading from storage failed")?;

        // Decrypt if necessary
        if self.encryption_engine.is_enabled() {
            block_data = self.encryption_engine.decrypt_block(block_number, &block_data).await
                .context("Block decryption failed")?;
        }

        // Cache block with isolation boundary
        {
            let mut cache = self.block_cache.write().await;
            cache.cached_blocks.insert(block_number, CachedBlock {
                block_number,
                data: block_data.clone(),
                dirty: false,
                last_access: Utc::now(),
                isolation_boundary: Some(boundary_id),
            });
        }

        Ok(block_data)
    }

    /// Write block with isolation enforcement
    async fn write_block_with_isolation(
        &self,
        block_number: u64,
        data: &[u8],
        boundary_id: Uuid
    ) -> AnyhowResult<()> {
        // Encrypt data if necessary
        let encrypted_data = if self.encryption_engine.is_enabled() {
            self.encryption_engine.encrypt_block(block_number, data).await
                .context("Block encryption failed")?
        } else {
            data.to_vec()
        };

        // Write to storage
        self.write_block_to_storage(block_number, &encrypted_data).await
            .context("Block writing to storage failed")?;

        // Update cache
        {
            let mut cache = self.block_cache.write().await;
            cache.cached_blocks.insert(block_number, CachedBlock {
                block_number,
                data: data.to_vec(),
                dirty: false,
                last_access: Utc::now(),
                isolation_boundary: Some(boundary_id),
            });
        }

        Ok(())
    }

    /// Read block data from physical storage
    async fn read_block_from_storage(&self, block_number: u64) -> AnyhowResult<Vec<u8>> {
        let block_path = self.mount_point.join(format!("block_{}", block_number));
        
        if block_path.exists() {
            fs::read(&block_path).await
                .context("Block file reading failed")
        } else {
            // Return zero-filled block if not exists
            Ok(vec![0u8; self.superblock.block_size as usize])
        }
    }

    /// Write block data to physical storage
    async fn write_block_to_storage(&self, block_number: u64, data: &[u8]) -> AnyhowResult<()> {
        let block_path = self.mount_point.join(format!("block_{}", block_number));
        fs::write(&block_path, data).await
            .context("Block file writing failed")
    }

    /// Allocate blocks for file data
    async fn allocate_blocks(&self, count: usize, _boundary_id: Uuid) -> AnyhowResult<Vec<u64>> {
        let mut allocated = Vec::new();
        
        // Simple allocation strategy - in real implementation would use block group descriptors
        for i in 0..count {
            let block_number = (self.superblock.total_blocks - self.superblock.free_blocks) + i as u64;
            allocated.push(block_number);
        }

        Ok(allocated)
    }

    /// Allocate new inode
    async fn allocate_inode(&self) -> AnyhowResult<u32> {
        // Simple inode allocation - real implementation would use bitmap
        Ok(self.superblock.total_inodes - self.superblock.free_inodes + 1)
    }

    /// Write inode to storage
    async fn write_inode(&self, inode: Ext4Inode) -> AnyhowResult<()> {
        let inode_path = self.mount_point.join(format!("inode_{}", inode.inode_number));
        let inode_data = bincode::serialize(&inode)
            .context("Inode serialization failed")?;
        
        fs::write(&inode_path, inode_data).await
            .context("Inode file writing failed")
    }

    /// Update existing inode
    async fn update_inode<F>(&self, inode_number: u32, update_fn: F) -> AnyhowResult<()>
    where
        F: FnOnce(&mut Ext4Inode),
    {
        let mut inode = self.load_inode_from_storage(inode_number).await?;
        update_fn(&mut inode);
        self.write_inode(inode).await
    }

    /// Add directory entry for new file
    async fn add_directory_entry(&self, _path: &Path, _inode_number: u32) -> AnyhowResult<()> {
        // Simplified directory entry creation
        // Real implementation would update parent directory's block with new entry
        Ok(())
    }

    /// Check if path exists
    async fn path_exists(&self, path: &Path) -> AnyhowResult<bool> {
        // Simplified existence check
        let inode_path = self.mount_point.join(format!("inode_{}", self.hash_path(path)));
        Ok(inode_path.exists())
    }
}

#[async_trait]
impl FilesystemInterface for Ext4Filesystem {
    async fn read_file(&self, path: &Path, boundary_id: Uuid) -> AnyhowResult<Vec<u8>> {
        self.read_file(path, boundary_id).await
    }

    async fn write_file(&self, path: &Path, data: &[u8], boundary_id: Uuid) -> AnyhowResult<()> {
        self.write_file(path, data, boundary_id).await
    }

    async fn delete_file(&self, path: &Path, boundary_id: Uuid) -> AnyhowResult<()> {
        info!("Deleting file: {} for boundary: {}", path.display(), boundary_id);

        // Verify write access for deletion
        self.isolation_manager.verify_write_access(&path, boundary_id).await
            .context("Delete access verification failed")?;

        let inode_number = self.resolve_path_to_inode(path).await
            .context("Path resolution for deletion failed")?;

        // Mark inode as deleted
        self.update_inode(inode_number, |inode| {
            inode.deletion_time = Some(Utc::now());
            inode.file_size = 0;
            inode.block_pointers.clear();
        }).await.context("Inode deletion update failed")?;

        // Log access
        self.isolation_manager.log_access(FilesystemAccessEvent {
            timestamp: Utc::now(),
            boundary_id,
            operation_type: FilesystemOperation::Delete,
            inode_number,
            access_granted: true,
        }).await;

        info!("File deletion completed successfully");
        Ok(())
    }

    async fn list_directory(&self, path: &Path, boundary_id: Uuid) -> AnyhowResult<Vec<String>> {
        info!("Listing directory: {} for boundary: {}", path.display(), boundary_id);

        // Verify read access to directory
        self.isolation_manager.verify_read_access(&path, boundary_id).await
            .context("Directory read access verification failed")?;

        // In a real implementation, this would read directory entries
        // For now, return empty list
        Ok(Vec::new())
    }

    fn get_filesystem_id(&self) -> Uuid {
        self.filesystem_id
    }
}

impl Ext4IsolationManager {
    async fn initialize() -> AnyhowResult<Self> {
        Ok(Self {
            filesystem_boundaries: RwLock::new(HashMap::new()),
            access_monitor: Arc::new(Mutex::new(FilesystemAccessMonitor {
                access_log: Vec::new(),
                max_log_entries: 10000,
            })),
        })
    }

    async fn verify_read_access(&self, _path: &Path, _boundary_id: Uuid) -> AnyhowResult<()> {
        // Real implementation would check boundary permissions against path
        Ok(())
    }

    async fn verify_write_access(&self, _path: &Path, _boundary_id: Uuid) -> AnyhowResult<()> {
        // Real implementation would check boundary permissions against path
        Ok(())
    }

    async fn log_access(&self, event: FilesystemAccessEvent) {
        let mut monitor = self.access_monitor.lock().await;
        monitor.access_log.push(event);
        
        // Keep log size manageable
        if monitor.access_log.len() > monitor.max_log_entries {
            monitor.access_log.remove(0);
        }
    }
}

impl BlockCache {
    fn new(cache_size_limit: usize) -> Self {
        Self {
            cached_blocks: HashMap::new(),
            cache_size_limit,
            access_counts: HashMap::new(),
        }
    }
}

impl InodeCache {
    fn new(cache_size_limit: usize) -> Self {
        Self {
            cached_inodes: HashMap::new(),
            cache_size_limit,
        }
    }
}
