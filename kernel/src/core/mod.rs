// =============================================================================
// CIBOS KERNEL MODULE ORGANIZATION - cibos/kernel/src/core/mod.rs
// =============================================================================

//! Core CIBOS kernel functionality
//! 
//! This module contains the essential kernel components that provide
//! process isolation, memory management, and system service coordination
//! in the microkernel architecture.

// External dependencies for core kernel functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use tokio::{sync::{Mutex, RwLock}, time::Duration};
use async_trait::async_trait;
use uuid::Uuid;

// Internal core kernel module exports
pub use self::scheduler::{ProcessScheduler, SchedulingConfiguration, SchedulingPolicy, SchedulerError};
pub use self::memory::{MemoryManager, VirtualMemoryManager, PhysicalMemoryManager, MemoryError};
pub use self::ipc::{InterProcessCommunication, SecureChannels, IPCProtocol, IPCError};
pub use self::syscall::{SystemCallInterface, SystemCallHandler, SyscallResult, SyscallError};
pub use self::isolation::{ProcessIsolation, ApplicationIsolation, IsolationManager, IsolationError};

// Shared type imports
use shared::types::isolation::{ProcessIsolationLevel, IsolationConfiguration, ResourceIsolation};
use shared::types::authentication::{ProcessCredentials, AuthenticationResult};
use shared::types::hardware::{HardwareInterface, DeviceCapabilities};
use shared::types::error::{KernelError, SystemError};
use shared::ipc::{SecureChannel, ChannelConfiguration, MessageProtocol};

// Core kernel module declarations
pub mod scheduler;
pub mod memory;
pub mod ipc;
pub mod syscall;
pub mod isolation;

/// Main kernel runtime structure coordinating all system services
#[derive(Debug)]
pub struct KernelRuntime {
    pub scheduler: std::sync::Arc<ProcessScheduler>,
    pub memory: std::sync::Arc<MemoryManager>,
    pub ipc: std::sync::Arc<InterProcessCommunication>,
    pub isolation: std::sync::Arc<IsolationManager>,
}

/// Kernel configuration loaded from CIBIOS handoff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfiguration {
    pub isolation_config: IsolationConfiguration,
    pub scheduling_config: SchedulingConfiguration,
    pub memory_config: MemoryConfiguration,
    pub ipc_config: IPCConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfiguration {
    pub page_size: u64,
    pub max_memory_per_process: u64,
    pub memory_isolation_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPCConfiguration {
    pub max_channels_per_process: u32,
    pub message_queue_size: u32,
    pub encryption_enabled: bool,
}

/// Process manager for application isolation and lifecycle
#[derive(Debug)]
pub struct ProcessManager {
    pub scheduler: std::sync::Arc<ProcessScheduler>,
    pub isolation: std::sync::Arc<IsolationManager>,
    pub memory: std::sync::Arc<MemoryManager>,
    pub active_processes: std::sync::Arc<RwLock<std::collections::HashMap<u32, ProcessInfo>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub isolation_boundary: Uuid,
    pub memory_allocation: ProcessMemoryAllocation,
    pub profile_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryAllocation {
    pub base_address: u64,
    pub size: u64,
    pub protection: MemoryProtectionFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtectionFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
