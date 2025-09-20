// =============================================================================
// CIBOS KERNEL x86 ARCHITECTURE - cibos/kernel/src/arch/x86/mod.rs
// x86 32-bit Kernel Architecture Implementation for Legacy Hardware Support
// =============================================================================

//! x86 32-bit kernel architecture implementation
//! 
//! This module provides kernel-level hardware abstraction for x86 32-bit systems,
//! including virtual memory management, interrupt handling, system call entry points,
//! and process context switching. Unlike the CIBIOS firmware modules, these components
//! operate within the kernel context after receiving control from CIBIOS.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;

// Internal kernel imports for x86 integration
use crate::core::memory::{MemoryManager, ProcessMemoryAllocation};
use crate::core::isolation::{IsolationManager, KernelIsolationBoundary};
use crate::core::scheduler::{ProcessScheduler, ProcessInfo};

// x86 specific module exports
pub use self::memory::{X86MemoryManager, X86VirtualMemory, X86PageTables};
pub use self::interrupts::{X86InterruptHandler, X86IDT, X86InterruptManager};
pub use self::syscalls::{X86SyscallHandler, X86SyscallEntry, X86SyscallInterface};
pub use self::context::{X86ContextSwitch, X86ProcessContext, X86ContextManager};
pub use self::entry::{X86KernelEntry, X86HandoffReceiver, X86KernelInitialization};

// Shared imports for x86 kernel integration
use shared::types::hardware::{ProcessorArchitecture, HardwareConfiguration};
use shared::types::isolation::{IsolationLevel, IsolationConfiguration};
use shared::types::error::{KernelError, ArchitectureError, MemoryError};
use shared::protocols::handoff::HandoffData;

// Module declarations for x86 kernel components
pub mod memory;
pub mod interrupts;
pub mod syscalls;
pub mod context;
pub mod entry;

/// x86 kernel runtime coordinating architecture-specific kernel operations
#[derive(Debug)]
pub struct X86KernelRuntime {
    memory_manager: Arc<X86MemoryManager>,
    interrupt_handler: Arc<X86InterruptHandler>,
    syscall_handler: Arc<X86SyscallHandler>,
    context_manager: Arc<X86ContextManager>,
    isolation_enforcer: Arc<KernelIsolationBoundary>,
}

/// x86 kernel configuration for 32-bit operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86KernelConfiguration {
    pub virtual_memory_enabled: bool,
    pub pae_enabled: bool,
    pub interrupt_handling_mode: InterruptMode,
    pub syscall_interface: SyscallInterface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterruptMode {
    Legacy,    // Traditional 8259 PIC
    APIC,      // Advanced PIC (if available)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallInterface {
    Interrupt,  // INT 0x80 traditional syscalls
    FastCall,   // SYSENTER if available
}

impl crate::arch::ArchKernelRuntime for X86KernelRuntime {
    /// Initialize x86 kernel runtime from CIBIOS handoff
    async fn initialize() -> AnyhowResult<Self> {
        info!("Initializing x86 kernel runtime");

        // Initialize x86 virtual memory management
        let memory_manager = Arc::new(X86MemoryManager::initialize().await
            .context("x86 memory manager initialization failed")?);

        // Initialize x86 interrupt handling
        let interrupt_handler = Arc::new(X86InterruptHandler::initialize().await
            .context("x86 interrupt handler initialization failed")?);

        // Initialize x86 system call handling
        let syscall_handler = Arc::new(X86SyscallHandler::initialize().await
            .context("x86 syscall handler initialization failed")?);

        // Initialize x86 context switching
        let context_manager = Arc::new(X86ContextManager::initialize().await
            .context("x86 context manager initialization failed")?);

        // Initialize kernel-level isolation enforcement
        let isolation_enforcer = Arc::new(KernelIsolationBoundary::new_x86().await
            .context("x86 kernel isolation boundary creation failed")?);

        info!("x86 kernel runtime initialization completed");

        Ok(Self {
            memory_manager,
            interrupt_handler,
            syscall_handler,
            context_manager,
            isolation_enforcer,
        })
    }

    /// Get processor architecture (x86 32-bit)
    fn get_architecture(&self) -> ProcessorArchitecture {
        ProcessorArchitecture::X86
    }

    /// Setup x86-specific isolation boundaries within kernel context
    async fn setup_isolation_boundaries(&self, config: &IsolationConfiguration) -> AnyhowResult<()> {
        info!("Setting up x86 kernel isolation boundaries");

        // Configure memory isolation using x86 page tables
        self.memory_manager.setup_memory_isolation(config).await
            .context("x86 memory isolation setup failed")?;

        // Configure interrupt isolation for process boundaries
        self.interrupt_handler.setup_interrupt_isolation(config).await
            .context("x86 interrupt isolation setup failed")?;

        // Configure syscall isolation for secure system call handling
        self.syscall_handler.setup_syscall_isolation(config).await
            .context("x86 syscall isolation setup failed")?;

        info!("x86 kernel isolation boundaries established successfully");
        Ok(())
    }

    /// Handle x86-specific interrupts within kernel context
    async fn handle_interrupt(&self, interrupt_vector: u32) -> AnyhowResult<()> {
        debug!("Handling x86 interrupt vector: {}", interrupt_vector);

        // Route interrupt to appropriate handler based on vector
        match interrupt_vector {
            0x20..=0x2F => {
                // Hardware interrupts (IRQ 0-15)
                self.interrupt_handler.handle_hardware_interrupt(interrupt_vector).await
                    .context("Hardware interrupt handling failed")?;
            }
            0x80 => {
                // System call interrupt
                self.syscall_handler.handle_syscall_interrupt().await
                    .context("System call interrupt handling failed")?;
            }
            0x00..=0x1F => {
                // CPU exceptions
                self.interrupt_handler.handle_cpu_exception(interrupt_vector).await
                    .context("CPU exception handling failed")?;
            }
            _ => {
                warn!("Unknown interrupt vector: {}", interrupt_vector);
                return Err(anyhow::anyhow!("Unknown interrupt vector: {}", interrupt_vector));
            }
        }

        Ok(())
    }
}
