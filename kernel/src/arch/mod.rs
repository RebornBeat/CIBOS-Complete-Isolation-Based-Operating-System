// =============================================================================
// CIBOS KERNEL ARCHITECTURE MODULE ORGANIZATION - cibos/kernel/src/arch/mod.rs
// Architecture-specific kernel implementations for different processors
// =============================================================================

//! Architecture-specific kernel implementations
//! 
//! This module provides processor-specific kernel functionality while maintaining
//! universal isolation guarantees across all supported architectures.

// Architecture-specific module declarations based on compilation target
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86")]
pub mod x86;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

// Architecture-specific re-exports for current compilation target
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{X86_64KernelRuntime, X86_64MemoryManager, X86_64InterruptHandler};

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{AArch64KernelRuntime, AArch64MemoryManager, AArch64ExceptionHandler};

#[cfg(target_arch = "x86")]
pub use self::x86::{X86KernelRuntime, X86MemoryManager, X86InterruptHandler};

#[cfg(target_arch = "riscv64")]
pub use self::riscv64::{RiscV64KernelRuntime, RiscV64MemoryManager, RiscV64InterruptHandler};

use shared::types::hardware::{ProcessorArchitecture, HardwareConfiguration};
use shared::types::isolation::{IsolationLevel, IsolationConfiguration};

/// Universal kernel runtime interface that works across all architectures
pub trait ArchKernelRuntime {
    /// Initialize architecture-specific kernel components
    async fn initialize() -> AnyhowResult<Self> where Self: Sized;
    
    /// Get current processor architecture
    fn get_architecture(&self) -> ProcessorArchitecture;
    
    /// Setup architecture-specific isolation boundaries  
    async fn setup_isolation_boundaries(&self, config: &IsolationConfiguration) -> AnyhowResult<()>;
    
    /// Handle architecture-specific interrupts or exceptions
    async fn handle_interrupt(&self, interrupt_vector: u32) -> AnyhowResult<()>;
}
