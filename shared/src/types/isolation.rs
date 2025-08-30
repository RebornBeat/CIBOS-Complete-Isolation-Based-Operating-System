// =============================================================================
// SHARED/SRC/TYPES/ISOLATION.RS - Isolation Boundary Types
// =============================================================================

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Isolation level enforcement - only maximum isolation supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    Complete, // Only level supported - mathematical isolation guarantees
}

/// Process isolation level for application boundaries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessIsolationLevel {
    Maximum, // All processes run in complete isolation
}

/// Application boundary definition for isolation enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationBoundary {
    pub boundary_id: Uuid,
    pub application_id: Uuid,
    pub memory_boundary: MemoryBoundary,
    pub storage_boundary: StorageBoundary,
    pub network_boundary: NetworkBoundary,
    pub process_boundary: ProcessBoundary,
}

/// Memory boundary configuration for isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBoundary {
    pub base_address: u64,
    pub size: u64,
    pub protection_flags: MemoryProtectionFlags,
}

/// Storage access boundary for file system isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBoundary {
    pub allowed_paths: Vec<String>,
    pub encryption_required: bool,
    pub read_only_paths: Vec<String>,
    pub isolated_storage_root: String,
}

/// Network access boundary for communication isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBoundary {
    pub allowed_destinations: Vec<String>,
    pub proxy_required: bool,
    pub traffic_isolation: bool,
    pub bandwidth_limit: Option<u64>,
}

/// Process execution boundary for CPU and scheduling isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBoundary {
    pub cpu_allocation: CpuAllocation,
    pub priority_level: ProcessPriority,
    pub isolation_level: IsolationLevel,
}

/// CPU allocation configuration within isolation boundary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAllocation {
    pub percentage: u8,
    pub dedicated_cores: Vec<u8>,
    pub time_slice_microseconds: u64,
}

/// Process priority levels for scheduling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessPriority {
    System,
    User,
    Background,
}

/// Memory protection flags for hardware enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtectionFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Complete boundary configuration for isolation enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryConfiguration {
    pub isolation_level: IsolationLevel,
    pub memory_boundary: MemoryBoundary,
    pub storage_boundary: StorageBoundary,
    pub network_boundary: NetworkBoundary,
    pub process_boundary: ProcessBoundary,
}

/// Isolation operation result reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationResult {
    pub success: bool,
    pub boundary_established: bool,
    pub isolation_level_achieved: IsolationLevel,
    pub error_message: Option<String>,
}

/// Resource isolation configuration for system resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceIsolation {
    pub memory_isolation: bool,
    pub storage_isolation: bool,
    pub network_isolation: bool,
    pub process_isolation: bool,
    pub hardware_isolation: bool,
}
