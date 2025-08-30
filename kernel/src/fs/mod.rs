// CIBOS KERNEL FILESYSTEM MODULE ORGANIZATION - cibos/kernel/src/fs/mod.rs
pub mod kernel_filesystem {
    //! Isolated filesystem services for CIBOS kernel
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use async_trait::async_trait;
    use uuid::Uuid;
    use std::sync::Arc;
    use std::path::PathBuf;
    use std::collections::HashMap;
    
    // Filesystem component exports
    pub use self::vfs::{VirtualFileSystem, FilesystemInterface, IsolatedFilesystem};
    pub use self::ext4::{Ext4Filesystem, Ext4Configuration, Ext4IsolationManager};
    pub use self::fat32::{Fat32Filesystem, Fat32Configuration, Fat32IsolationManager};
    pub use self::encryption::{FilesystemEncryption, EncryptedStorage, KeyedFilesystem};
    
    // Filesystem module declarations
    pub mod vfs;
    pub mod ext4;
    pub mod fat32;
    pub mod encryption;
    
    /// Virtual filesystem with complete isolation between applications
    #[derive(Debug)]
    pub struct VirtualFileSystem {
        pub mounted_filesystems: HashMap<String, Arc<dyn FilesystemInterface>>,
        pub isolation_manager: FilesystemIsolationManager,
        pub encryption_manager: FilesystemEncryption,
    }
    
    #[derive(Debug)]
    pub struct FilesystemIsolationManager {
        pub isolation_boundaries: HashMap<Uuid, FilesystemBoundary>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FilesystemBoundary {
        pub boundary_id: Uuid,
        pub allowed_paths: Vec<PathBuf>,
        pub read_only_paths: Vec<PathBuf>,
        pub encryption_required: bool,
    }
}
